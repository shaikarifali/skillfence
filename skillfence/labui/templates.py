"""The Lab Explorer's single HTML page — a clean, professional layout in
the spirit of a real security-training platform (a card grid of
categories, a clear detail page with a sidebar table of contents), not a
themed skin. Live data throughout: every field comes from the real lab
files and the real engine, nothing here is staged.

Ships inside the pip package and has to render with zero internet access
(an air-gapped machine is a real, supported case, same reasoning as
`dashboard.templates`), so there's no webfont/CDN request — the type
stack leans on solid system UI fonts instead.
"""

from __future__ import annotations

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SkillFence Lab Explorer</title>
<style>
:root{
  --bg:#F4F6F8; --surface:#FFFFFF; --surface-2:#F0F2F5; --surface-3:#E6E9EE;
  --ink:#1B2430; --ink-dim:#5B6674; --ink-faint:#8A93A0;
  --rule:#E1E5EA; --rule-strong:#CBD2DA;
  --accent:#8A6A1F; --accent-strong:#6E5417; --accent-wash:#FBF3DE;
  --crit:#C4302B; --crit-wash:#FBE9E8;
  --high:#B5620C; --high-wash:#FBF0DE;
  --med:#93790C; --med-wash:#F8F3D9;
  --ok:#1C7C3F; --ok-wash:#E4F5E9;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", Consolas, monospace;
  --shadow: 0 1px 2px rgba(20,30,40,.05), 0 4px 14px -6px rgba(20,30,40,.12);
  --shadow-lift: 0 2px 5px rgba(20,30,40,.07), 0 10px 26px -8px rgba(20,30,40,.18);
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#12161C; --surface:#1A1F27; --surface-2:#212832; --surface-3:#2A323D;
    --ink:#E7EBEF; --ink-dim:#9BA6B3; --ink-faint:#6B7683;
    --rule:#2A323D; --rule-strong:#39424E;
    --accent:#E8C46B; --accent-strong:#F2D88A; --accent-wash:#332711;
    --crit:#F2867E; --crit-wash:#341E1C;
    --high:#E8B26B; --high-wash:#332711;
    --med:#DFD07D; --med-wash:#302B14;
    --ok:#7FDA9E; --ok-wash:#152D1E;
    --shadow: 0 1px 2px rgba(0,0,0,.3), 0 4px 16px -6px rgba(0,0,0,.4);
    --shadow-lift: 0 2px 6px rgba(0,0,0,.35), 0 12px 30px -10px rgba(0,0,0,.55);
  }
}
:root{ --code-bg:#0F1216; --code-text:#D8DEE4; --code-rule:#242B33; --code-accent:#6FE0C4; }

*{box-sizing:border-box;}
html,body{height:100%;}
body{ background:var(--bg); color:var(--ink); margin:0; font-family:var(--sans); font-size:14.5px; line-height:1.55; -webkit-font-smoothing:antialiased; }
.mono{ font-family:var(--mono); }
h1,h2,h3{ text-wrap:balance; font-weight:700; margin:0; }
p{ margin:0; }
::selection{ background:var(--accent-wash); }
button,select,input{ font:inherit; }
a{ color:var(--accent-strong); text-decoration:none; }
a:hover{ text-decoration:underline; }

.topbar{ display:flex; align-items:center; gap:14px; padding:0 22px; height:54px; background:var(--surface); border-bottom:1px solid var(--rule); position:sticky; top:0; z-index:3; }
.wordmark{ display:flex; align-items:center; gap:9px; font-weight:800; font-size:15px; letter-spacing:-.01em; white-space:nowrap; cursor:pointer; }
.wordmark .mark{ width:22px; height:22px; border-radius:5px; background:var(--accent); display:flex; align-items:center; justify-content:center; color:#fff; font-size:12px; font-weight:800; }
.wordmark .name{ color:var(--ink); }
.wordmark .name b{ color:var(--accent-strong); }
.crumbs{ color:var(--ink-faint); font-size:12.5px; }
.crumbs a{ color:var(--ink-dim); }
.crumbs .sep{ margin:0 6px; color:var(--rule-strong); }
.root-path{ color:var(--ink-faint); font-size:11px; font-family:var(--mono); }
.spacer{ flex:1; }
.topbar button{ background:var(--surface-2); color:var(--ink-dim); border:1px solid var(--rule); border-radius:6px; padding:6px 13px; font-size:12.5px; font-weight:600; cursor:pointer; }
.topbar button:hover{ border-color:var(--accent); color:var(--accent-strong); }

.shell{ display:flex; min-height:calc(100vh - 54px); }
#sidebar{ width:290px; flex-shrink:0; overflow-y:auto; border-right:1px solid var(--rule); background:var(--surface); }
.filter-wrap{ padding:14px; border-bottom:1px solid var(--rule); position:sticky; top:0; background:var(--surface); z-index:1; }
.filter-wrap input{ width:100%; background:var(--surface-2); color:var(--ink); border:1px solid var(--rule); border-radius:6px; padding:8px 10px; font-size:13px; }
.filter-wrap input:focus{ outline:none; border-color:var(--accent); }
.cat-header{ padding:12px 16px 6px; font-size:12px; font-weight:700; color:var(--ink); border-top:1px solid var(--rule); }
.cat-header:first-child{ border-top:none; }
.cat-header .cat-sub{ font-size:10px; font-weight:600; letter-spacing:.03em; text-transform:uppercase; color:var(--ink-faint); margin-top:2px; }
.lab-row{ padding:9px 16px; cursor:pointer; border-left:3px solid transparent; }
.lab-row:hover{ background:var(--surface-2); }
.lab-row.selected{ background:var(--accent-wash); border-left-color:var(--accent); }
.lab-row .skill{ font-weight:600; font-size:13px; color:var(--ink); }
.lab-row .slug{ color:var(--ink-faint); font-size:11px; font-family:var(--mono); margin-top:2px; }
.dot{ display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:5px; vertical-align:middle; }
.dot.malicious{ background:var(--crit); } .dot.benign{ background:var(--ok); }
.verdict-label{ font-size:10.5px; font-weight:600; color:var(--ink-faint); text-transform:uppercase; letter-spacing:.03em; }

#main{ flex:1; overflow-y:auto; }
.page{ max-width:1040px; margin:0 auto; padding:36px 40px 70px; }

/* -- landing / category grid -- */
.hero h1{ font-size:26px; }
.hero p{ color:var(--ink-dim); font-size:14.5px; margin-top:8px; max-width:70ch; line-height:1.65; }
.stat-strip{ display:flex; gap:0; margin-top:24px; border:1px solid var(--rule); border-radius:10px; overflow:hidden; background:var(--surface); box-shadow:var(--shadow); }
.stat{ flex:1; padding:14px 18px; border-right:1px solid var(--rule); }
.stat:last-child{ border-right:none; }
.stat .num{ font-size:22px; font-weight:800; color:var(--accent-strong); }
.stat .label{ font-size:10.5px; color:var(--ink-faint); text-transform:uppercase; letter-spacing:.03em; margin-top:2px; }
.grid-label{ margin:32px 0 14px; font-size:12px; font-weight:700; color:var(--ink-faint); text-transform:uppercase; letter-spacing:.04em; }
.cat-grid{ display:grid; grid-template-columns:repeat(auto-fill, minmax(230px, 1fr)); gap:14px; }
.cat-card{ background:var(--surface); border:1px solid var(--rule); border-radius:10px; padding:18px; cursor:pointer; box-shadow:var(--shadow); transition:transform .12s ease, box-shadow .12s ease; }
.cat-card:hover{ transform:translateY(-2px); box-shadow:var(--shadow-lift); border-color:var(--rule-strong); }
.cat-card .code{ font-family:var(--mono); font-size:11px; color:var(--accent-strong); font-weight:700; }
.cat-card .title{ font-size:16px; font-weight:700; margin-top:6px; color:var(--ink); }
.cat-card .subtitle{ font-size:11.5px; color:var(--ink-faint); margin-top:2px; font-style:italic; }
.cat-card .desc{ font-size:12.5px; color:var(--ink-dim); margin-top:8px; line-height:1.5; min-height:36px; }
.cat-card .count{ margin-top:14px; display:flex; align-items:center; justify-content:space-between; font-size:12px; color:var(--ink-faint); }
.cat-card .count b{ color:var(--ink); font-size:13px; }

/* -- lab detail -- */
.eyebrow{ font-size:12px; font-weight:700; color:var(--accent-strong); text-transform:uppercase; letter-spacing:.03em; }
.title{ font-size:27px; font-weight:800; margin-top:6px; }
.mission{ color:var(--ink-dim); font-size:14px; margin-top:8px; max-width:72ch; line-height:1.6; }
.slug{ color:var(--ink-faint); font-size:12px; font-family:var(--mono); margin-top:10px; }
.meta-row{ margin-top:14px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }

.badge{ display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:700; padding:3px 10px; border-radius:100px; }
.badge::before{ content:''; width:6px; height:6px; border-radius:50%; background:currentColor; }
.badge-critical{ color:var(--crit); background:var(--crit-wash); }
.badge-high{ color:var(--high); background:var(--high-wash); }
.badge-medium{ color:var(--med); background:var(--med-wash); }
.badge-low, .badge-allow{ color:var(--ok); background:var(--ok-wash); }
.badge-none{ color:var(--ink-faint); background:var(--surface-2); }
.pill{ display:inline-block; font-size:11px; font-weight:600; color:var(--ink-dim); background:var(--surface-2); border:1px solid var(--rule); padding:2px 9px; border-radius:5px; font-family:var(--mono); }

.section{ margin-top:34px; }
.section-title{ font-size:13px; font-weight:700; color:var(--ink); margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid var(--rule); }

.card{ background:var(--surface); border:1px solid var(--rule); border-radius:10px; box-shadow:var(--shadow); overflow:hidden; }
table.kv{ width:100%; border-collapse:collapse; }
table.kv th{ text-align:left; font-size:10.5px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; color:var(--ink-faint); padding:9px 16px; border-bottom:1px solid var(--rule); background:var(--surface-2); }
table.kv td{ padding:10px 16px; border-bottom:1px solid var(--rule); font-size:13px; vertical-align:top; }
table.kv tr:last-child td{ border-bottom:none; }
table.kv td.k{ color:var(--ink-dim); width:170px; font-weight:600; }
table.kv td.v{ font-family:var(--mono); font-size:12.5px; }

.tabs{ display:flex; border-bottom:1px solid var(--rule-strong); background:var(--surface-2); }
.tab{ font-size:12.5px; font-weight:600; color:var(--ink-dim); padding:10px 18px; cursor:pointer; border-bottom:2px solid transparent; }
.tab.active{ color:var(--accent-strong); border-bottom-color:var(--accent); background:var(--surface); }
.tab:hover:not(.active){ color:var(--ink); }
.tab-body{ background:var(--code-bg); max-height:380px; overflow-y:auto; padding:16px 18px; }
.tab-body pre{ margin:0; font-family:var(--mono); font-size:12.5px; line-height:1.7; white-space:pre-wrap; word-break:break-word; color:var(--code-text); }
.tab-panel{ display:none; } .tab-panel.active{ display:block; }

.run-bar{ display:flex; align-items:center; gap:12px; padding:16px 18px; flex-wrap:wrap; }
.run-bar label{ color:var(--ink-dim); font-size:12.5px; font-weight:600; }
.run-bar select{ background:var(--surface); color:var(--ink); border:1px solid var(--rule-strong); border-radius:6px; padding:7px 10px; font-size:13px; }
.run-btn{ display:flex; align-items:center; gap:7px; background:var(--accent); color:#fff; border:none; border-radius:6px; padding:8px 18px; font-size:13px; font-weight:700; cursor:pointer; }
.run-btn:hover:not(:disabled){ background:var(--accent-strong); }
.run-btn:disabled{ opacity:.4; cursor:default; }
#run-status{ font-size:12.5px; color:var(--ink-dim); }

table.results{ width:100%; border-collapse:collapse; font-size:13px; }
table.results th{ text-align:left; color:var(--ink-faint); font-weight:700; font-size:10.5px; letter-spacing:.04em; text-transform:uppercase; padding:9px 16px; border-bottom:1px solid var(--rule); background:var(--surface-2); }
table.results td{ padding:10px 16px; border-bottom:1px solid var(--rule); vertical-align:top; }
table.results tr:last-child td{ border-bottom:none; }
tr.finding-row.critical td:first-child{ box-shadow:inset 3px 0 0 var(--crit); }
tr.finding-row.high td:first-child{ box-shadow:inset 3px 0 0 var(--high); }
tr.finding-row.medium td:first-child{ box-shadow:inset 3px 0 0 var(--med); }
tr.finding-row.low td:first-child{ box-shadow:inset 3px 0 0 var(--ok); }
.status-ok{ color:var(--ok); font-weight:700; } .status-blocked{ color:var(--crit); font-weight:700; } .status-error{ color:var(--med); font-weight:700; }
.cds-track{ width:70px; height:6px; background:var(--surface-3); border-radius:3px; overflow:hidden; display:inline-block; vertical-align:middle; }
.cds-fill{ height:100%; }
.why{ margin:5px 0 0; padding-left:16px; color:var(--ink-dim); font-size:12px; }
.no-findings{ display:flex; align-items:center; gap:8px; color:var(--ok); font-size:13.5px; font-weight:700; padding:16px 18px; }

.terminal{ margin-top:14px; }
.terminal-body{ background:var(--code-bg); padding:16px 18px; font-family:var(--mono); font-size:12px; line-height:1.75; white-space:pre-wrap; color:var(--code-text); max-height:340px; overflow-y:auto; }

#empty{ max-width:480px; margin:16px auto; text-align:center; color:var(--ink-dim); font-size:14px; line-height:1.7; }

@media (prefers-reduced-motion: reduce){ *{ transition:none !important; } }
button:focus-visible, .lab-row:focus-visible, .tab:focus-visible, .cat-card:focus-visible{ outline:2px solid var(--accent); outline-offset:2px; }
@media (max-width: 760px){ #sidebar{ width:220px; } .page{ padding:20px 18px; } .title{ font-size:21px; } }
</style>
</head>
<body>
<div class="topbar">
  <div class="wordmark" id="home-link">
    <span class="mark"><svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 2 L20 5 V11 C20 16 16.5 20 12 22 C7.5 20 4 16 4 11 V5 Z" fill="#fff" opacity=".92"/></svg></span>
    <span class="name">SkillFence <b>Lab Explorer</b></span>
  </div>
  <div class="crumbs" id="crumbs"></div>
  <div class="spacer"></div>
  <div class="root-path" id="root-path"></div>
  <button id="refresh-btn">Refresh</button>
</div>
<div class="shell">
  <div id="sidebar">
    <div class="filter-wrap"><input id="filter" type="text" placeholder="Search labs…"></div>
    <div id="lab-list"></div>
  </div>
  <div id="main"></div>
</div>
<script>
const CATEGORIES = {
  AST01: "Malicious Skills", AST02: "Supply Chain Compromise", AST03: "Over-Privileged Skills",
  AST04: "Insecure Metadata", AST05: "Untrusted External Instructions", AST06: "Weak Isolation",
  AST07: "Update Drift", AST08: "Poor Scanning", AST09: "No Governance", AST10: "Cross-Platform Reuse",
};
// The campaign's own chapter names for each OWASP category (from the
// project's Knightfall plan, verbatim) -- shown alongside the technical
// AST0x code and OWASP name everywhere, never in place of them.
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
function badge(sev) {
  const s = (sev || "none").toLowerCase();
  return `<span class="badge badge-${esc(s)}">${esc(s)}</span>`;
}
function lastSegment(name) { const parts = name.split("/"); return parts[parts.length - 1]; }
function catName(ast) { return CATEGORIES[ast] || ast; }

async function loadLabs() {
  const root = await fetchJSON("/api/root");
  document.getElementById("root-path").textContent = root.path;
  ALL_LABS = await fetchJSON("/api/labs");
  renderSidebar();
  showHome();
}

function renderSidebar() {
  const filterText = document.getElementById("filter").value.trim().toLowerCase();
  const list = document.getElementById("lab-list");
  list.innerHTML = "";
  const byAst = {};
  for (const lab of ALL_LABS) {
    if (filterText && !(lab.name.toLowerCase().includes(filterText) || (lab.skill_name || "").toLowerCase().includes(filterText))) continue;
    (byAst[lab.ast] = byAst[lab.ast] || []).push(lab);
  }
  const asts = Object.keys(byAst).sort();
  if (asts.length === 0) {
    list.innerHTML = '<div style="padding:16px;color:var(--ink-faint);font-size:12px;">No labs match.</div>';
    return;
  }
  for (const ast of asts) {
    const ch = chapterOf(ast);
    const header = document.createElement("div");
    header.className = "cat-header";
    header.innerHTML = `<div>Chapter ${ch.roman} &mdash; ${esc(ch.name)}</div><div class="cat-sub">${esc(ast)} &middot; ${esc(catName(ast))}</div>`;
    list.appendChild(header);
    for (const lab of byAst[ast]) {
      const row = document.createElement("div");
      row.className = "lab-row" + (lab.name === selectedName ? " selected" : "");
      row.onclick = () => selectLab(lab.name);
      const verdict = lab.malicious === null ? "" :
        `<div class="verdict-label"><span class="dot ${lab.malicious ? "malicious" : "benign"}"></span>${lab.malicious ? "malicious" : "benign"}</div>`;
      row.innerHTML = `<div class="skill">${esc(lab.skill_name)}</div><div class="slug">${esc(lastSegment(lab.name))}</div>${verdict}`;
      list.appendChild(row);
    }
  }
}

function setCrumbs(parts) {
  document.getElementById("crumbs").innerHTML = parts.map((p, i) =>
    i === parts.length - 1 ? `<span>${esc(p.label)}</span>` : `<a href="#" data-nav="${i}">${esc(p.label)}</a><span class="sep">/</span>`
  ).join("");
  document.querySelectorAll("[data-nav]").forEach(a => {
    a.onclick = (e) => { e.preventDefault(); const i = Number(a.getAttribute("data-nav")); if (i === 0) showHome(); };
  });
}

function showHome() {
  selectedName = null;
  renderSidebar();
  setCrumbs([{label: "Overview"}]);
  const total = ALL_LABS.length;
  const malicious = ALL_LABS.filter(l => l.malicious === true).length;
  const benign = ALL_LABS.filter(l => l.malicious === false).length;
  const byAst = {};
  for (const lab of ALL_LABS) (byAst[lab.ast] = byAst[lab.ast] || []).push(lab);
  const asts = Object.keys(byAst).sort();
  const cards = asts.map(ast => {
    const ch = chapterOf(ast);
    return `
    <div class="cat-card" data-ast="${esc(ast)}">
      <div class="code">${esc(ast)} &middot; Chapter ${ch.roman}</div>
      <div class="title">${esc(ch.name)}</div>
      <div class="subtitle">${esc(catName(ast))}</div>
      <div class="desc">${byAst[ast].map(l => esc(l.skill_name)).slice(0, 3).join(", ")}${byAst[ast].length > 3 ? ", …" : ""}</div>
      <div class="count"><span>Labs</span><b>${byAst[ast].length}</b></div>
    </div>`;
  }).join("");
  document.getElementById("main").innerHTML = `
    <div class="page">
      <div class="hero">
        <h1>SkillFence Lab Explorer</h1>
        <p>Ten chapters, one per OWASP Agentic Skills Top 10 category. A live view over every lab under this root —
        real declared capabilities, real <code>SKILL.md</code>/<code>README.md</code> content, and a Run control that
        executes the lab through the real SkillFence engine and shows its real findings. Nothing on this page is staged.</p>
      </div>
      <div class="stat-strip">
        <div class="stat"><div class="num">${total}</div><div class="label">Labs discovered</div></div>
        <div class="stat"><div class="num">${malicious}</div><div class="label">Malicious</div></div>
        <div class="stat"><div class="num">${benign}</div><div class="label">Benign controls</div></div>
        <div class="stat"><div class="num">${asts.length}</div><div class="label">OWASP categories</div></div>
      </div>
      <div class="grid-label">Browse by category</div>
      <div class="cat-grid">${cards}</div>
    </div>`;
  document.querySelectorAll(".cat-card").forEach(card => {
    card.onclick = () => { document.getElementById("filter").value = card.getAttribute("data-ast"); renderSidebar(); };
  });
}

function evRow(k, v) { return `<tr><td class="k">${esc(k)}</td><td class="v">${v}</td></tr>`; }

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
  if (security && security.scanned) rows.push(evRow("security.scanned", `true (${esc(security.scan_tool || "unspecified tool")})`));
  return `<div class="card"><table class="kv"><tbody>${rows.join("")}</tbody></table></div>`;
}

function renderFileTabs(name, skillMd, readme) {
  const tabs = [], panels = [];
  if (skillMd) { tabs.push(["skillmd", "SKILL.md"]); panels.push(["skillmd", skillMd]); }
  if (readme) { tabs.push(["readme", "README.md"]); panels.push(["readme", readme]); }
  if (tabs.length === 0) return "";
  const key = name.replace(/[^a-zA-Z0-9]/g, "-");
  const tabsHtml = tabs.map((t, i) => `<div class="tab${i === 0 ? " active" : ""}" data-panel="ft-${key}-${t[0]}">${t[1]}</div>`).join("");
  const panelsHtml = panels.map((p, i) => `<div class="tab-panel${i === 0 ? " active" : ""}" id="ft-${key}-${p[0]}"><pre>${esc(p[1])}</pre></div>`).join("");
  return `<div class="card"><div class="tabs">${tabsHtml}</div><div class="tab-body">${panelsHtml}</div></div>`;
}

function renderGroundTruth(gt) {
  if (!gt) return "";
  const ef = gt.expected_finding || {};
  const isMalicious = gt.ground_truth && gt.ground_truth.malicious;
  return `<div class="meta-row">
    <span class="pill">expected: ${isMalicious ? "malicious" : "benign"}</span>
    ${(ef.ast || []).map(t => `<span class="pill">${esc(t)}</span>`).join("")}
    ${ef.severity_at_least ? `<span class="pill">severity &ge; ${esc(ef.severity_at_least)}</span>` : ""}
  </div>`;
}

async function selectLab(name) {
  selectedName = name;
  renderSidebar();
  const detail = await fetchJSON(`/api/lab/${name.split("/").map(encodeURIComponent).join("/")}`);
  setCrumbs([{label: "Overview"}, {label: detail.ast}, {label: detail.skill_name}]);
  const missionTitle = detail.ground_truth && detail.ground_truth.title;
  const mission = missionTitle ? `<div class="mission">${esc(missionTitle)}</div>` : "";
  document.getElementById("main").innerHTML = `
    <div class="page">
      <div class="eyebrow">Chapter ${esc(chapterOf(detail.ast).roman)} &mdash; ${esc(chapterOf(detail.ast).name)} <span style="color:var(--ink-faint);font-weight:600;">&middot; ${esc(detail.ast)} &middot; ${esc(catName(detail.ast))}</span></div>
      <div class="title">${esc(detail.skill_name)}</div>
      ${mission}
      <div class="slug">${esc(detail.name)} &middot; v${esc(detail.version)}${detail.session_count ? ` &middot; run ${detail.session_count}&times; before` : " &middot; never run"}</div>
      <div class="meta-row">${(detail.purpose || []).map(p => `<span class="pill">${esc(p)}</span>`).join("")}</div>
      ${renderGroundTruth(detail.ground_truth)}

      <div class="section">
        <div class="section-title">Declared capabilities</div>
        ${renderCapabilities(detail.capabilities, detail.security)}
      </div>

      <div class="section">
        <div class="section-title">Files</div>
        ${renderFileTabs(detail.name, detail.skill_md, detail.readme) || "<p style='color:var(--ink-faint);font-size:13px;'>No SKILL.md or README.md found.</p>"}
      </div>

      <div class="section">
        <div class="section-title">Run</div>
        <div class="card">
          <div class="run-bar">
            <label>Decision on gate</label>
            <select id="decision-select">
              <option value="reject">reject</option>
              <option value="approve_once">approve_once</option>
              <option value="allow_for_session">allow_for_session</option>
              <option value="allow_scoped">allow_scoped</option>
              <option value="quarantine_skill">quarantine_skill</option>
            </select>
            <button class="run-btn" id="run-btn" ${detail.runnable ? "" : "disabled"}>Run</button>
            <span id="run-status"></span>
          </div>
        </div>
        <div id="run-result"></div>
      </div>
    </div>
  `;
  document.querySelectorAll(".tab").forEach(tab => {
    tab.onclick = () => {
      const tabs = tab.parentElement, body = tabs.nextElementSibling;
      tabs.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      body.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      document.getElementById(tab.getAttribute("data-panel")).classList.add("active");
    };
  });
  if (detail.runnable) document.getElementById("run-btn").onclick = () => runLab(detail.name);
}

function renderSteps(steps) {
  if (!steps.length) return "";
  const rows = steps.map(s => `<tr><td>${esc(s.action)}</td><td class="status-${esc(s.status)}">${esc(s.status)}</td><td>${esc(s.detail || "")}</td></tr>`).join("");
  return `<div class="section-title" style="margin-top:22px;">Run steps</div><div class="card"><table class="results"><thead><tr><th>Action</th><th>Status</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderFindings(findings) {
  const title = '<div class="section-title" style="margin-top:22px;">Findings</div>';
  if (!findings.length) return title + '<div class="card"><div class="no-findings">&#10003; No findings — every action stayed within declared capability / low risk.</div></div>';
  const rank = {critical:4, high:3, medium:2, low:1, none:0};
  const sorted = [...findings].sort((a, b) => (rank[b.severity]||0) - (rank[a.severity]||0));
  const rows = sorted.map(f => {
    const cdsPct = Math.round((f.cds || 0) * 100);
    const cdsColor = {ALLOW:"var(--ok)", WARN:"var(--med)", GATE:"var(--high)", BLOCK:"var(--crit)"}[f.cds_band] || "var(--ink-faint)";
    const tags = (f.ast || []).map(t => `<span class="pill">${esc(t)}</span>`).join(" ");
    const why = (f.why_flagged || []).map(r => `<li>${esc(r)}</li>`).join("");
    return `<tr class="finding-row ${esc(f.severity)}">
      <td>${badge(f.severity)}</td>
      <td><div style="font-weight:700;">${esc(f.title)}</div><div style="margin-top:4px;">${tags}</div><ul class="why">${why}</ul></td>
      <td class="mono" style="font-size:12px;">${esc(f.resource || "-")}</td>
      <td><span class="cds-track"><span class="cds-fill" style="width:${cdsPct}%;background:${cdsColor}"></span></span>
          <div style="font-size:11px;color:var(--ink-faint);margin-top:2px;">${((f.cds === undefined || f.cds === null) ? 0 : f.cds).toFixed(2)} (${esc(f.cds_band || "-")})</div></td>
      <td style="font-size:12.5px;">${esc(f.human_decision || f.status || "pending")}</td>
    </tr>`;
  }).join("");
  const explainBlocks = sorted.map(f => esc(f.explain)).join("\\n\\n---\\n\\n");
  return `${title}<div class="card"><table class="results"><thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Drift Score</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="terminal"><div class="terminal-body">${explainBlocks}</div></div></div>`;
}

async function runLab(name) {
  const btn = document.getElementById("run-btn"), status = document.getElementById("run-status");
  const decision = document.getElementById("decision-select").value;
  btn.disabled = true;
  status.textContent = "running…";
  try {
    const result = await fetchJSON(`/api/lab/${name.split("/").map(encodeURIComponent).join("/")}/run?decision=${encodeURIComponent(decision)}`, {method: "POST"});
    status.textContent = `invocation #${result.invocation_number}`;
    document.getElementById("run-result").innerHTML = renderSteps(result.steps) + renderFindings(result.findings);
  } catch (e) {
    status.textContent = "error: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("refresh-btn").onclick = loadLabs;
document.getElementById("home-link").onclick = showHome;
document.getElementById("filter").oninput = renderSidebar;
loadLabs();
</script>
</body>
</html>
"""
