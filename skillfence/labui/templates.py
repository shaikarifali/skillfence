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
  --serif: "Palatino Linotype", Palatino, "Book Antiqua", Georgia, "Times New Roman", serif;
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
.serif{ font-family:var(--serif); }
::selection{ background:var(--accent-wash); }
button,select,input{ font:inherit; }
a{ color:var(--accent-strong); text-decoration:none; }
a:hover{ text-decoration:underline; }

.topbar{ display:flex; align-items:center; gap:14px; padding:0 22px; height:54px; background:var(--surface); border-bottom:1px solid var(--rule); position:sticky; top:0; z-index:3; }
.wordmark{ display:flex; align-items:center; gap:9px; font-weight:800; font-size:15.5px; letter-spacing:-.01em; white-space:nowrap; cursor:pointer; font-family:var(--serif); }
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

.shell{ display:flex; height:calc(100vh - 54px); }
#sidebar{ width:290px; flex-shrink:0; overflow-y:auto; min-height:0; border-right:1px solid var(--rule); background:var(--surface); }
.filter-wrap{ padding:14px; border-bottom:1px solid var(--rule); position:sticky; top:0; background:var(--surface); z-index:1; }
.filter-wrap input{ width:100%; background:var(--surface-2); color:var(--ink); border:1px solid var(--rule); border-radius:6px; padding:8px 10px; font-size:13px; }
.filter-wrap input:focus{ outline:none; border-color:var(--accent); }
.cat-header{ padding:12px 16px 6px; font-size:12px; font-weight:700; color:var(--ink); border-top:1px solid var(--rule); border-left:3px solid var(--chapter, transparent); cursor:pointer; }
.cat-header:hover{ background:var(--surface-2); }
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

#main{ flex:1; overflow-y:auto; min-height:0; }
.page{ max-width:1040px; margin:0 auto; padding:36px 40px 70px; }

/* -- landing / category grid -- */
.hero{ position:relative; padding:28px 30px; border-radius:14px; overflow:hidden; background:var(--surface); border:1px solid var(--rule); box-shadow:var(--shadow); }
.hero::before{ content:''; position:absolute; inset:0; background:
    repeating-linear-gradient(115deg, transparent 0 18px, rgba(138,106,31,.05) 18px 19px),
    linear-gradient(135deg, var(--accent-wash), transparent 60%); pointer-events:none; }
.hero-inner{ position:relative; }
.hero h1{ font-size:28px; font-family:var(--serif); letter-spacing:-.01em; }
.hero p{ color:var(--ink-dim); font-size:14.5px; margin-top:10px; max-width:70ch; line-height:1.65; }
.stat-strip{ display:flex; gap:0; margin-top:24px; border:1px solid var(--rule); border-radius:10px; overflow:hidden; background:var(--surface); box-shadow:var(--shadow); }
.stat{ flex:1; padding:14px 18px; border-right:1px solid var(--rule); }
.stat:last-child{ border-right:none; }
.stat .num{ font-size:22px; font-weight:800; color:var(--accent-strong); font-family:var(--serif); }
.stat .label{ font-size:10.5px; color:var(--ink-faint); text-transform:uppercase; letter-spacing:.03em; margin-top:2px; }
.grid-label{ margin:32px 0 14px; font-size:12px; font-weight:700; color:var(--ink-faint); text-transform:uppercase; letter-spacing:.04em; }
.cat-grid{ display:grid; grid-template-columns:repeat(auto-fill, minmax(250px, 1fr)); gap:14px; }
.cat-card{ position:relative; background:var(--surface); border:1px solid var(--rule); border-radius:10px; padding:18px; padding-top:22px; cursor:pointer; box-shadow:var(--shadow); transition:transform .12s ease, box-shadow .12s ease; overflow:hidden; }
.cat-card::before{ content:''; position:absolute; top:0; left:0; right:0; height:4px; background:var(--chapter); }
.cat-card:hover{ transform:translateY(-3px); box-shadow:var(--shadow-lift); border-color:var(--rule-strong); }
.cat-card .head-row{ display:flex; align-items:flex-start; gap:12px; }
.cat-card .shield-wrap{ flex-shrink:0; width:38px; height:38px; }
.cat-card .code{ font-family:var(--mono); font-size:10.5px; color:var(--chapter); font-weight:700; }
.cat-card .title{ font-size:16.5px; font-weight:700; margin-top:3px; color:var(--ink); font-family:var(--serif); }
.cat-card .subtitle{ font-size:11.5px; color:var(--ink-faint); margin-top:2px; font-style:italic; }
.cat-card .desc{ font-size:12.5px; color:var(--ink-dim); margin-top:10px; line-height:1.5; min-height:36px; }
.cat-card .count{ margin-top:14px; padding-top:12px; border-top:1px solid var(--rule); display:flex; align-items:center; justify-content:space-between; font-size:12px; color:var(--ink-faint); }
.cat-card .count b{ color:var(--ink); font-size:13px; }

/* -- chapter overview page -- */
.chapter-banner{ position:relative; padding:34px 34px; border-radius:14px; overflow:hidden; color:#fff; background:var(--chapter); box-shadow:var(--shadow-lift); }
.chapter-banner::before{ content:''; position:absolute; inset:0; background:
    repeating-linear-gradient(115deg, transparent 0 16px, rgba(255,255,255,.06) 16px 17px),
    radial-gradient(120% 140% at 100% 0%, rgba(255,255,255,.16), transparent 55%); pointer-events:none; }
.chapter-banner-inner{ position:relative; display:flex; align-items:center; gap:24px; }
.chapter-banner .shield-wrap{ width:76px; height:76px; flex-shrink:0; filter:drop-shadow(0 3px 6px rgba(0,0,0,.25)); }
.chapter-banner .code{ font-family:var(--mono); font-size:12px; font-weight:700; opacity:.85; letter-spacing:.03em; }
.chapter-banner h1{ font-family:var(--serif); font-size:30px; color:#fff; margin-top:4px; }
.chapter-banner .subtitle{ font-size:13.5px; opacity:.9; margin-top:4px; font-style:italic; }
.issue-fix-grid{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:24px; }
.issue-fix-grid .card{ padding:20px; }
.issue-fix-grid h3{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; margin-bottom:10px; display:flex; align-items:center; gap:7px; }
.issue-fix-grid h3.issue-h{ color:var(--crit); }
.issue-fix-grid h3.fix-h{ color:var(--ok); }
.issue-fix-grid p{ font-size:13.5px; line-height:1.65; color:var(--ink-dim); }
.evidence-strip{ margin-top:16px; display:flex; align-items:center; gap:10px; padding:12px 16px; border-radius:8px; background:var(--surface-2); border:1px dashed var(--rule-strong); font-size:12.5px; color:var(--ink-dim); }
.evidence-strip b{ color:var(--ink); }
@media (max-width: 640px){ .issue-fix-grid{ grid-template-columns:1fr; } .chapter-banner-inner{ flex-direction:column; align-items:flex-start; gap:14px; } }

/* -- lab detail -- */
.eyebrow{ font-size:12px; font-weight:700; color:var(--chapter, var(--accent-strong)); text-transform:uppercase; letter-spacing:.03em; display:flex; align-items:center; gap:8px; cursor:pointer; }
.eyebrow .shield-wrap{ width:20px; height:20px; flex-shrink:0; }
.eyebrow:hover{ text-decoration:underline; }
.title{ font-size:27px; font-weight:800; margin-top:8px; font-family:var(--serif); }
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
.reveal-btn{ background:var(--surface); color:var(--ink-dim); border:1px dashed var(--rule-strong); border-radius:6px; padding:9px 16px; font-size:12.5px; font-weight:600; cursor:pointer; width:100%; text-align:left; }
.reveal-btn:hover{ border-color:var(--accent); color:var(--accent-strong); border-style:solid; }

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
// `ast` is literally the lab's top-level directory name (see labui/data.py
// _ast_of()) -- true for the ten AST0x chapters, but also "BENIGN" and
// "CAPSTONE", which are real top-level directories and not OWASP
// categories at all. Never treat those two as a "Chapter ?".
function isChapter(ast) { return /^AST\d+$/.test(ast); }
const GROUP_LABELS = {
  BENIGN: {title: "Benign Controls", subtitle: "false-positive checks — every one of these should stay clean"},
  CAPSTONE: {title: "Capstone", subtitle: "one story chaining multiple chapters into a single realistic attack"},
};
function groupLabel(ast) { return GROUP_LABELS[ast] || {title: ast, subtitle: ""}; }

// One color per chapter ("house"), evenly spaced around the wheel --
// purely a wayfinding/decorative layer (icons, accent bars, the chapter
// banner), never used for anything severity-related, which stays on the
// fixed crit/high/med/ok scale everywhere else.
const CHAPTER_COLORS = {
  AST01: "#B24A42", AST02: "#B9702E", AST03: "#A9862A", AST04: "#6E8A3A",
  AST05: "#3F8A5B", AST06: "#2E8A82", AST07: "#3E6FA8", AST08: "#5B4FA8",
  AST09: "#8A4499", AST10: "#A83E6B",
};
function chapterColor(ast) { return CHAPTER_COLORS[ast] || "#8A6A1F"; }

// A small hand-drawn glyph per chapter, sitting inside the shared shield
// outline -- simple geometric primitives, not illustration, so they stay
// legible at 20-76px and cost nothing to render (inline SVG, no assets).
const GLYPHS = {
  AST01: '<rect x="8.5" y="10" width="7" height="2.4" rx="1"/><path d="M8 15 L11 12.5 L13 15 L16 12.5" stroke-width="1.4" fill="none"/>',
  AST02: '<path d="M12 8 C9.5 11 9.5 14 12 17 C14.5 14 14.5 11 12 8 Z"/>',
  AST03: '<path d="M7.5 15 L9 9 L12 12.5 L15 9 L16.5 15 Z"/><rect x="7.5" y="15" width="9" height="1.8" rx=".5"/>',
  AST04: '<circle cx="12" cy="12" r="4.2" fill="none" stroke-width="1.5"/><path d="M9 15.5 L7.5 18 L10 17.2 Z"/><path d="M15 15.5 L16.5 18 L14 17.2 Z"/>',
  AST05: '<circle cx="8.5" cy="12" r="1.6" fill="none" stroke-width="1.3"/><circle cx="15.5" cy="12" r="1.6" fill="none" stroke-width="1.3"/><rect x="8.5" y="10.4" width="7" height="3.2"/><line x1="9.8" y1="12" x2="14.2" y2="12" stroke="var(--surface)" stroke-width=".9"/>',
  AST06: '<rect x="7" y="9" width="4" height="2.6"/><rect x="13" y="9" width="4" height="2.6"/><rect x="10" y="12.4" width="4" height="2.6"/><rect x="7" y="15.8" width="3" height="2.6"/><rect x="14" y="15.8" width="3" height="2.6"/>',
  AST07: '<path d="M8 8 H16 L12 12.5 Z"/><path d="M8 17 H16 L12 12.5 Z"/>',
  AST08: '<path d="M7.5 12 C9.5 8.5 14.5 8.5 16.5 12 C14.5 15.5 9.5 15.5 7.5 12 Z" fill="none" stroke-width="1.4"/><circle cx="12" cy="12" r="1.7"/><line x1="7" y1="16.5" x2="17" y2="7.5" stroke-width="1.4"/>',
  AST09: '<circle cx="12" cy="12" r="3" fill="none" stroke-width="1.3"/><circle cx="12" cy="7.3" r="1.1"/><circle cx="16.2" cy="10.3" r="1.1"/><circle cx="16.2" cy="14.9" r="1.1"/><circle cx="12" cy="16.7" r="1.1"/><circle cx="7.8" cy="14.9" r="1.1"/><circle cx="7.8" cy="10.3" r="1.1"/>',
  AST10: '<circle cx="12" cy="12" r="5" fill="none" stroke-width="1.4"/><path d="M8 8 L11 13 L9 17 M16 8.5 L13 12.5 L15.5 16.5" stroke-width="1.2" fill="none"/>',
};

// Shared shield outline (the same crest used in the topbar wordmark) with
// a chapter-tinted wash + the glyph above layered inside, at whatever size
// the caller needs -- one motif reused everywhere a chapter is referenced.
function shieldIcon(ast, size) {
  const color = chapterColor(ast);
  const glyph = GLYPHS[ast] || "";
  return `<svg class="shield-wrap" width="${size}" height="${size}" viewBox="0 0 24 24" style="color:${color}">
    <path d="M12 2 L20 5 V11 C20 16 16.5 20 12 22 C7.5 20 4 16 4 11 V5 Z" fill="${color}" opacity=".16" stroke="${color}" stroke-width="1.1"/>
    <g fill="currentColor" stroke="currentColor">${glyph}</g>
  </svg>`;
}

// The issue/fix content for each chapter -- distilled from this suite's
// own DVAS README (the "### The story" section + "Key Mitigation"/
// "Real-World Evidence" columns for each AST category), not generic OWASP
// boilerplate. Reference/documentation content, same status as CATEGORIES
// and CHAPTERS above -- not "live" lab data, but not staged either.
const ISSUES = {
  AST01: {
    issue: "A skill's manifest and description can describe an entirely legitimate task while its actual behavior does something else in the same run — reading credentials, scanning for secrets, exfiltrating data — because nothing about a successful-looking result tells anyone the hidden action didn't also happen.",
    fix: "Never trust a manifest or description as a behavioral contract. Trace every action a skill actually takes against its declared capabilities in real time, and gate anything undeclared or sensitive before it executes — not after reviewing the code once at install time.",
    evidence: "ClawHavoc (1,184 skills), ToxicSkills (76 payloads)",
  },
  AST02: {
    issue: "A skill that passed review once can change after that review, silently, through an update whose manifest is treated as self-certifying. A new capability lands in the same diff as an innocuous changelog line, or a version jumps suspiciously (1.0 → 3.0, no history in between) — a shape a one-time install review can never catch, because it never runs again.",
    fix: "Compare every update against the skill's true original manifest, not just the internal consistency of the new one. Flag any capability that's new since the last version a human actually approved, and treat an unexplained version jump as evidence on its own.",
    evidence: "ClawHub registry collapse, Claude Code CVE-2025-59536",
  },
  AST03: {
    issue: "Most over-privileged skills aren't malicious — a manifest just states a negative ('no network,' 'no secrets access') that was true once and never re-verified. Nothing in a typical install flow checks that claim again at runtime.",
    fix: "Enforce least-privilege at runtime, not just at review time. Treat every declared 'false'/'none' as a live constraint the runtime checks on every single action, not documentation trusted forever after one read.",
    evidence: "280+ credential-leaking skills found in the wild (Snyk, Feb 2026)",
  },
  AST04: {
    issue: "A manifest schema can only say so much — a blanket network toggle with no domain list, a single secrets boolean with no scope, a name and purpose text standing in for verified identity. Metadata like this gets trusted by default because there's rarely anything else to check at install time, which is exactly what brand-impersonation and payload-smuggling attacks exploit.",
    fix: "Validate metadata against actual runtime destinations, not just schema shape — a declared domain has to match the real one byte for byte, and a plausible name/purpose is never proof of identity. Parse manifests defensively so a field can't be read more literally than a human reviewer would read it.",
    evidence: "Fake 'Google' skill impersonation; YAML payload smuggled into a SKILL.md file",
  },
  AST05: {
    issue: "The skill itself can be completely legitimate — accurate manifest, declared domain — and still get compromised through content it fetches honestly at runtime, from a source that changes independently of any version anyone reviewed. A public proof-of-concept (the 'Air' PoC) bypassed every scanner tested this way, because every one of them inspected the skill package, and the payload was never in the package.",
    fix: "Scan every piece of fetched content for instruction-like language before acting on it — and don't stop at one fetch: rescan the accumulated session content on every new fetch, since a payload can be deliberately split across multiple, individually-clean documents.",
    evidence: "Air PoC bypassed all scanners tested; ~26,000 agents estimated exposed",
  },
  AST06: {
    issue: "Comparing a requested path against a declared glob says nothing about whether the resolved, real filesystem path a skill touches ever leaves the sandbox it's supposed to be confined to. A path can carry the exact same prefix as every legitimate in-workspace reference and still walk straight out of the sandbox once its `..` segments are actually resolved.",
    fix: "Independently verify that every resolved path stays inside the skill's own sandbox root — enforced regardless of what the manifest declares and regardless of how innocuous the request string looks, with a fail-safe refusal on any resolved escape.",
    evidence: "Shared-host multi-skill deployments with no enforced sandbox boundary between skills",
  },
  AST07: {
    issue: "A skill's manifest can stay completely unchanged while its real, observed behavior gains a capability it never exercised before — because the declared scope was already broad enough to cover it, or because a permission sat dormant since it was first approved 'just in case' until it wasn't.",
    fix: "Keep a cross-invocation behavioral baseline for every skill, independent of whether its manifest or version ever changed, and flag any capability token that's genuinely new relative to that skill's own history — not just new relative to the manifest.",
    evidence: "Skills whose real behavior drifts with no version bump and no declared-capability change",
  },
  AST08: {
    issue: "A skill can carry a manifest attestation that it already passed a static security scan, naming the tool — and the scan can still be worthless, because a scanner tuned to code-layer patterns (exec, curl, subprocess) has nothing to say about a plain-language directive sitting in prose, buried in a long document, or phrased one sentence differently than the exact signature it was tuned to catch.",
    fix: "Detect instruction-shaped language at runtime, independent of position, phrasing, or a fixed signature — and never treat a declared scan attestation as a substitute for that live enforcement.",
    evidence: "A declared 'already scanned' attestation directly contradicted by a live runtime finding",
  },
  AST09: {
    issue: "An organization running many skills has no answer to 'which of these were ever actually reviewed, and which still have a standing elevated grant nobody's checked since?' unless something tracks it across the whole fleet — one skill's clean runtime behavior says nothing about governance at the fleet level.",
    fix: "Maintain a fleet-wide inventory of review status and grant recency, not per-skill approval alone. Flag any skill that's never been reviewed at all, and any active grant that predates its own skill's last review.",
    evidence: "Skills sitting installed with standing elevated permissions nobody has ever verified",
  },
  AST10: {
    issue: "A skill ported from one agent platform to another goes through an automated porting tool that has to guess at every capability that doesn't map cleanly onto the new schema — and its default is rarely 'ask a human.' The result is a manifest that quietly widened during migration, with no human ever consciously granting the new access.",
    fix: "Diff a ported manifest against the skill's true original — not just check the ported one for internal consistency — and treat any capability that's new since the original platform as untrusted until reviewed, the same as any other unexplained capability drift.",
    evidence: "A porting tool's own template defaults silently widening a manifest during migration",
  },
};

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
    const header = document.createElement("div");
    header.className = "cat-header";
    if (isChapter(ast)) {
      const ch = chapterOf(ast);
      header.style.setProperty("--chapter", chapterColor(ast));
      header.innerHTML = `<div>Chapter ${ch.roman} &mdash; ${esc(ch.name)}</div><div class="cat-sub">${esc(ast)} &middot; ${esc(catName(ast))}</div>`;
      header.onclick = () => showChapter(ast);
    } else {
      const g = groupLabel(ast);
      header.innerHTML = `<div>${esc(g.title)}</div><div class="cat-sub">${esc(ast)}</div>`;
      header.onclick = () => showGroup(ast);
    }
    list.appendChild(header);
    for (const lab of byAst[ast]) {
      const row = document.createElement("div");
      row.className = "lab-row" + (lab.name === selectedName ? " selected" : "");
      row.onclick = () => selectLab(lab.name);
      // Deliberately no malicious/benign indicator here -- showing the
      // verdict in the nav list would spoil every lab before it's even
      // opened. Read the skill, run it, then reveal the analysis.
      row.innerHTML = `<div class="skill">${esc(lab.skill_name)}</div><div class="slug">${esc(lastSegment(lab.name))}</div>`;
      list.appendChild(row);
    }
  }
}

// Each part is {label, action?} -- the last part is always plain text (the
// current page), every earlier one with an `action` becomes a clickable
// crumb that runs it.
function setCrumbs(parts) {
  document.getElementById("crumbs").innerHTML = parts.map((p, i) => {
    const isLast = i === parts.length - 1;
    const text = (!isLast && p.action) ? `<a href="#" data-nav="${i}">${esc(p.label)}</a>` : `<span>${esc(p.label)}</span>`;
    return isLast ? text : `${text}<span class="sep">/</span>`;
  }).join("");
  document.querySelectorAll("[data-nav]").forEach(a => {
    const i = Number(a.getAttribute("data-nav"));
    a.onclick = (e) => { e.preventDefault(); parts[i].action(); };
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
  const chapterAsts = asts.filter(isChapter);
  const otherAsts = asts.filter(a => !isChapter(a));
  const cards = chapterAsts.map(ast => {
    const ch = chapterOf(ast);
    const issue = ISSUES[ast];
    const teaser = issue ? issue.issue.split(/(?<=[.!?])\s/)[0] : byAst[ast].map(l => esc(l.skill_name)).slice(0, 3).join(", ");
    return `
    <div class="cat-card" data-ast="${esc(ast)}" style="--chapter:${chapterColor(ast)}">
      <div class="head-row">
        ${shieldIcon(ast, 38)}
        <div>
          <div class="code">${esc(ast)} &middot; Chapter ${ch.roman}</div>
          <div class="title">${esc(ch.name)}</div>
          <div class="subtitle">${esc(catName(ast))}</div>
        </div>
      </div>
      <div class="desc">${esc(teaser)}</div>
      <div class="count"><span>Labs</span><b>${byAst[ast].length}</b></div>
    </div>`;
  }).join("");
  const otherCards = otherAsts.map(ast => {
    const g = groupLabel(ast);
    return `
    <div class="cat-card" data-group="${esc(ast)}" style="--chapter:var(--rule-strong)">
      <div class="code">${esc(ast)}</div>
      <div class="title">${esc(g.title)}</div>
      <div class="subtitle">${esc(g.subtitle)}</div>
      <div class="desc">${byAst[ast].map(l => esc(l.skill_name)).slice(0, 3).join(", ")}${byAst[ast].length > 3 ? ", …" : ""}</div>
      <div class="count"><span>Labs</span><b>${byAst[ast].length}</b></div>
    </div>`;
  }).join("");
  document.getElementById("main").innerHTML = `
    <div class="page">
      <div class="hero"><div class="hero-inner">
        <h1>SkillFence Lab Explorer</h1>
        <p>Ten chapters, one per OWASP Agentic Skills Top 10 category. A live view over every lab under this root —
        real declared capabilities, real <code>SKILL.md</code>/<code>README.md</code> content, and a Run control that
        executes the lab through the real SkillFence engine and shows its real findings. Nothing on this page is staged.</p>
      </div></div>
      <div class="stat-strip">
        <div class="stat"><div class="num">${total}</div><div class="label">Labs discovered</div></div>
        <div class="stat"><div class="num">${malicious}</div><div class="label">Malicious</div></div>
        <div class="stat"><div class="num">${benign}</div><div class="label">Benign controls</div></div>
        <div class="stat"><div class="num">${chapterAsts.length}</div><div class="label">OWASP categories</div></div>
      </div>
      <div class="grid-label">Browse by chapter</div>
      <div class="cat-grid">${cards}</div>
      ${otherCards ? `<div class="grid-label">Beyond the ten chapters</div><div class="cat-grid">${otherCards}</div>` : ""}
    </div>`;
  document.querySelectorAll(".cat-card[data-ast]").forEach(card => {
    card.onclick = () => showChapter(card.getAttribute("data-ast"));
  });
  document.querySelectorAll(".cat-card[data-group]").forEach(card => {
    card.onclick = () => showGroup(card.getAttribute("data-group"));
  });
}

// A plain, unthemed listing for the two real top-level directories that
// aren't OWASP categories at all (BENIGN, CAPSTONE) -- no shield, no
// invented "issue"/"fix" content, just the labs.
function showGroup(ast) {
  selectedName = null;
  document.getElementById("filter").value = "";
  renderSidebar();
  const g = groupLabel(ast);
  const labs = ALL_LABS.filter(l => l.ast === ast);
  setCrumbs([{label: "Overview", action: showHome}, {label: g.title}]);
  const labCards = labs.map(lab => `
    <div class="cat-card" data-lab="${esc(lab.name)}">
      <div class="code">${esc(lastSegment(lab.name))}</div>
      <div class="title" style="font-size:15px;">${esc(lab.skill_name)}</div>
      <div class="subtitle">${lab.malicious === false ? "benign control" : "run &rarr; observe &rarr; decide"}</div>
    </div>`).join("");
  document.getElementById("main").innerHTML = `
    <div class="page">
      <div class="hero"><div class="hero-inner">
        <h1>${esc(g.title)}</h1>
        <p>${esc(g.subtitle)} &mdash; ${labs.length} lab${labs.length === 1 ? "" : "s"}.</p>
      </div></div>
      <div class="grid-label">Labs</div>
      <div class="cat-grid">${labCards}</div>
    </div>`;
  document.querySelectorAll(".cat-grid .cat-card[data-lab]").forEach(card => {
    card.onclick = () => selectLab(card.getAttribute("data-lab"));
  });
}

function showChapter(ast) {
  selectedName = null;
  document.getElementById("filter").value = "";
  renderSidebar();
  const ch = chapterOf(ast);
  const issue = ISSUES[ast] || {issue: "", fix: "", evidence: ""};
  const labs = ALL_LABS.filter(l => l.ast === ast);
  setCrumbs([{label: "Overview", action: showHome}, {label: `Chapter ${ch.roman}`}]);
  const labCards = labs.map(lab => `
    <div class="cat-card" data-lab="${esc(lab.name)}" style="--chapter:${chapterColor(ast)}">
      <div class="code">${esc(lastSegment(lab.name))}</div>
      <div class="title" style="font-size:15px;">${esc(lab.skill_name)}</div>
      <div class="subtitle">${lab.malicious === false ? "benign control" : "run &rarr; observe &rarr; decide"}</div>
    </div>`).join("");
  document.getElementById("main").innerHTML = `
    <div class="page">
      <div class="chapter-banner" style="--chapter:${chapterColor(ast)}"><div class="chapter-banner-inner">
        ${shieldIcon(ast, 76)}
        <div>
          <div class="code">${esc(ast)} &middot; ${esc(catName(ast))}</div>
          <h1>Chapter ${ch.roman} &mdash; ${esc(ch.name)}</h1>
          <div class="subtitle">${labs.length} lab${labs.length === 1 ? "" : "s"} in this chapter</div>
        </div>
      </div></div>
      <div class="issue-fix-grid">
        <div class="card"><h3 class="issue-h">&#9888; The Issue</h3><p>${esc(issue.issue)}</p></div>
        <div class="card"><h3 class="fix-h">&#10003; How To Fix It</h3><p>${esc(issue.fix)}</p></div>
      </div>
      ${issue.evidence ? `<div class="evidence-strip">&#128220; <b>Real-world evidence:</b> ${esc(issue.evidence)}</div>` : ""}
      <div class="grid-label">Labs in this chapter</div>
      <div class="cat-grid">${labCards}</div>
    </div>`;
  document.querySelectorAll(".cat-grid .cat-card[data-lab]").forEach(card => {
    card.onclick = () => selectLab(card.getAttribute("data-lab"));
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

function renderSolution(detail) {
  const gt = detail.ground_truth;
  const isMalicious = gt && gt.ground_truth && gt.ground_truth.malicious;
  const ef = (gt && gt.expected_finding) || {};
  const verdictPills = gt ? `<div class="meta-row">
    <span class="pill">verdict: ${isMalicious ? "malicious" : "benign"}</span>
    ${(ef.ast || []).map(t => `<span class="pill">${esc(t)}</span>`).join("")}
    ${ef.severity_at_least ? `<span class="pill">severity &ge; ${esc(ef.severity_at_least)}</span>` : ""}
  </div>` : "";
  const caseTitle = gt && gt.title ? `<p style="font-weight:700;margin-bottom:10px;">${esc(gt.title)}</p>` : "";
  const readme = detail.readme
    ? `<div class="card" style="margin-top:14px;"><div class="tab-body" style="max-height:none;"><pre>${esc(detail.readme)}</pre></div></div>`
    : "<p style='color:var(--ink-faint);font-size:13px;'>No README.md found.</p>";
  return `
    <div class="section">
      <button class="reveal-btn" id="reveal-btn">Show analysis &amp; expected verdict</button>
      <div id="solution-body" style="display:none; margin-top:16px;">
        ${caseTitle}
        ${verdictPills}
        ${readme}
      </div>
    </div>`;
}

async function selectLab(name) {
  selectedName = name;
  renderSidebar();
  const detail = await fetchJSON(`/api/lab/${name.split("/").map(encodeURIComponent).join("/")}`);
  const chaptered = isChapter(detail.ast);
  const groupCrumbLabel = chaptered ? `Chapter ${chapterOf(detail.ast).roman}` : groupLabel(detail.ast).title;
  const goToGroup = () => chaptered ? showChapter(detail.ast) : showGroup(detail.ast);
  setCrumbs([
    {label: "Overview", action: showHome},
    {label: groupCrumbLabel, action: goToGroup},
    {label: detail.skill_name},
  ]);
  const eyebrowHtml = chaptered
    ? `${shieldIcon(detail.ast, 20)}Chapter ${esc(chapterOf(detail.ast).roman)} &mdash; ${esc(chapterOf(detail.ast).name)} <span style="color:var(--ink-faint);font-weight:600;">&middot; ${esc(detail.ast)} &middot; ${esc(catName(detail.ast))}</span>`
    : esc(groupLabel(detail.ast).title);
  document.getElementById("main").innerHTML = `
    <div class="page">
      <div class="eyebrow" id="eyebrow-link" style="--chapter:${chaptered ? chapterColor(detail.ast) : "var(--accent-strong)"}">${eyebrowHtml}</div>
      <div class="title">${esc(detail.skill_name)}</div>
      <div class="slug">${esc(detail.name)} &middot; v${esc(detail.version)}${detail.session_count ? ` &middot; run ${detail.session_count}&times; before` : " &middot; never run"}</div>
      <div class="meta-row">${(detail.purpose || []).map(p => `<span class="pill">${esc(p)}</span>`).join("")}</div>

      <div class="section">
        <div class="section-title">Declared capabilities</div>
        ${renderCapabilities(detail.capabilities, detail.security)}
      </div>

      <div class="section">
        <div class="section-title">SKILL.md</div>
        ${renderFileTabs(detail.name, detail.skill_md, null) || "<p style='color:var(--ink-faint);font-size:13px;'>No SKILL.md found.</p>"}
      </div>

      <div class="section">
        <div class="section-title">1. Observe</div>
        <p style="color:var(--ink-dim); font-size:13px; margin-bottom:12px;">Runs the skill for real and records every real action it takes —
        nothing is blocked in this mode, so you see its true behavior before deciding anything.</p>
        <div class="card">
          <div class="run-bar">
            <button class="run-btn" id="observe-btn" ${detail.runnable ? "" : "disabled"}>Observe</button>
            <span id="observe-status"></span>
          </div>
        </div>
        <div id="observe-result"></div>
      </div>

      <div class="section" id="decide-section" style="display:none;">
        <div class="section-title">2. Decide</div>
        <p style="color:var(--ink-dim); font-size:13px; margin-bottom:12px;">Based on what you just observed, choose how the human gate should
        respond, then run it again with enforcement actually on.</p>
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
            <button class="run-btn" id="enforce-btn">Enforce</button>
            <span id="enforce-status"></span>
          </div>
        </div>
        <div id="enforce-result"></div>
      </div>

      ${renderSolution(detail)}
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
  document.getElementById("eyebrow-link").onclick = goToGroup;
  const revealBtn = document.getElementById("reveal-btn");
  if (revealBtn) revealBtn.onclick = () => {
    const body = document.getElementById("solution-body");
    const open = body.style.display !== "none";
    body.style.display = open ? "none" : "block";
    revealBtn.textContent = open ? "Show analysis & expected verdict" : "Hide analysis & expected verdict";
  };
  if (detail.runnable) {
    document.getElementById("observe-btn").onclick = () => observeLab(detail.name);
    document.getElementById("enforce-btn").onclick = () => enforceLab(detail.name);
  }
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

async function observeLab(name) {
  const btn = document.getElementById("observe-btn"), status = document.getElementById("observe-status");
  btn.disabled = true;
  status.textContent = "observing…";
  try {
    // decision=approve_once is a required parameter but never consulted in
    // observe mode -- the human gate is never actually asked anything here,
    // see run_lab_via_ui()'s docstring. Same convention `skillfence observe`
    // itself uses.
    const url = `/api/lab/${name.split("/").map(encodeURIComponent).join("/")}/run?decision=approve_once&mode=observe`;
    const result = await fetchJSON(url, {method: "POST"});
    status.textContent = `invocation #${result.invocation_number} · observed`;
    document.getElementById("observe-result").innerHTML = renderSteps(result.steps) + renderFindings(result.findings);
    document.getElementById("decide-section").style.display = "block";
  } catch (e) {
    status.textContent = "error: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

async function enforceLab(name) {
  const btn = document.getElementById("enforce-btn"), status = document.getElementById("enforce-status");
  const decision = document.getElementById("decision-select").value;
  btn.disabled = true;
  status.textContent = "enforcing…";
  try {
    const url = `/api/lab/${name.split("/").map(encodeURIComponent).join("/")}/run?decision=${encodeURIComponent(decision)}&mode=enforce`;
    const result = await fetchJSON(url, {method: "POST"});
    status.textContent = `invocation #${result.invocation_number} · enforced`;
    document.getElementById("enforce-result").innerHTML = renderSteps(result.steps) + renderFindings(result.findings);
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
