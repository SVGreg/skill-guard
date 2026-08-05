#!/usr/bin/env python3
"""Render evaluation/reports/stats.json into a single self-contained interactive
HTML report (evaluation/reports/REPORT.html by default).

The page embeds the stats blob and renders everything client-side: summary cards,
severity / risk-tier / top-rule / AST distributions, and a searchable, filterable,
sortable per-skill explorer with expandable findings. No external assets — inline
CSS + vanilla JS only — so it works offline and as a hosted artifact.

Env:
  STATS_NAME   input stats file under evaluation/reports/  (default stats.json)
  HTML_NAME    output HTML file under evaluation/reports/   (default REPORT.html)
  REPORT_TITLE page title                                   (default below)
"""
import json
import os

HERE = os.path.dirname(__file__)
REPORTS = os.path.join(HERE, "..", "reports")
STATS_NAME = os.environ.get("STATS_NAME", "stats.json")
HTML_NAME = os.environ.get("HTML_NAME", "REPORT.html")
TITLE = os.environ.get("REPORT_TITLE", "skill-guard — Corpus Security Evaluation")

SRC_DESC = {
    "clawhub": "ClawHub registry — top skills by download count",
    "skillsmp": "SkillsMP — GitHub-indexed skills (recent, many repos)",
    "orgs": "Vendor repos — trailofbits, stripe, supabase, tinybird",
    "anthropic": "github.com/anthropics/skills example skills",
    "clawhub_more": "ClawHub — additional download-ranked batch",
    "skillject": "SkillJect — carrier skills used in malicious-skill research",
}

TEMPLATE = r"""<title>__TITLE__</title>
<style>
:root {
  --accent: #0f9e8e; --accent-soft: #12a59422; --accent-line: #12a59455;
  --bg: #f5f8f8; --panel: #ffffff; --panel-2: #eef3f2; --line: #d7e0de;
  --ink: #10201e; --ink-2: #46565340; --muted: #5c6b68; --faint: #8a9995;
  --crit: #cf3236; --high: #d95f14; --med: #b9821a; --low: #64757f; --info: #8593a0;
  --pass: #218a58; --fail: #cf3236; --warn: #b9821a;
  --shadow: 0 1px 2px #10201e0f, 0 6px 20px #10201e0a;
  --mono: ui-monospace, "Cascadia Code", "SF Mono", "Menlo", "Consolas", monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1417; --panel: #141c1f; --panel-2: #182226; --line: #24312f;
    --ink: #e7efec; --ink-2: #e7efec14; --muted: #93a49f; --faint: #64756f;
    --accent: #2dd4bf; --accent-soft: #2dd4bf1f; --accent-line: #2dd4bf44;
    --crit: #f36d70; --high: #f7924b; --med: #e6bd5c; --low: #8a99a3; --info: #7d8b97;
    --pass: #48c088; --fail: #f36d70; --warn: #e6bd5c;
    --shadow: 0 1px 2px #0006, 0 8px 28px #0004;
  }
}
:root[data-theme="light"] {
  --accent: #0f9e8e; --accent-soft: #12a59422; --accent-line: #12a59455;
  --bg: #f5f8f8; --panel: #ffffff; --panel-2: #eef3f2; --line: #d7e0de;
  --ink: #10201e; --muted: #5c6b68; --faint: #8a9995;
  --crit: #cf3236; --high: #d95f14; --med: #b9821a; --low: #64757f; --info: #8593a0;
  --pass: #218a58; --fail: #cf3236; --warn: #b9821a;
  --shadow: 0 1px 2px #10201e0f, 0 6px 20px #10201e0a;
}
:root[data-theme="dark"] {
  --bg: #0e1417; --panel: #141c1f; --panel-2: #182226; --line: #24312f;
  --ink: #e7efec; --muted: #93a49f; --faint: #64756f;
  --accent: #2dd4bf; --accent-soft: #2dd4bf1f; --accent-line: #2dd4bf44;
  --crit: #f36d70; --high: #f7924b; --med: #e6bd5c; --low: #8a99a3; --info: #7d8b97;
  --pass: #48c088; --fail: #f36d70; --warn: #e6bd5c;
  --shadow: 0 1px 2px #0006, 0 8px 28px #0004;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font-family: var(--sans);
  line-height: 1.5; -webkit-font-smoothing: antialiased; }
.wrap { max-width: 1120px; margin: 0 auto; padding: 0 20px 72px; }
h1, h2, h3 { text-wrap: balance; margin: 0; }
.mono { font-family: var(--mono); }
.num { font-variant-numeric: tabular-nums; }

/* header */
header { position: sticky; top: 0; z-index: 20; background: color-mix(in srgb, var(--bg) 88%, transparent);
  backdrop-filter: blur(8px); border-bottom: 1px solid var(--line); }
.head-in { max-width: 1120px; margin: 0 auto; padding: 14px 20px; display: flex;
  align-items: center; gap: 14px; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 650; letter-spacing: -.01em; }
.brand .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent);
  box-shadow: 0 0 0 4px var(--accent-soft); }
.brand small { font-family: var(--mono); font-weight: 500; color: var(--muted); font-size: 12px; }
.spacer { flex: 1; }
.toggle { font-family: var(--mono); font-size: 12px; color: var(--muted); background: var(--panel);
  border: 1px solid var(--line); border-radius: 8px; padding: 7px 11px; cursor: pointer; }
.toggle:hover { color: var(--ink); border-color: var(--accent-line); }

/* hero */
.hero { padding: 40px 0 22px; }
.eyebrow { font-family: var(--mono); font-size: 12px; letter-spacing: .12em; text-transform: uppercase;
  color: var(--accent); margin-bottom: 12px; }
.hero h1 { font-size: clamp(26px, 4vw, 40px); line-height: 1.1; letter-spacing: -.02em; }
.hero p { color: var(--muted); max-width: 64ch; margin: 14px 0 0; font-size: 15px; }

/* cards */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin: 26px 0; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 18px 18px 16px;
  box-shadow: var(--shadow); position: relative; overflow: hidden; }
.card .k { font-family: var(--mono); font-size: 11px; letter-spacing: .08em; text-transform: uppercase;
  color: var(--faint); }
.card .v { font-size: 34px; font-weight: 680; letter-spacing: -.02em; margin-top: 6px;
  font-variant-numeric: tabular-nums; }
.card .sub { color: var(--muted); font-size: 13px; margin-top: 4px; }
.card .rail { position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--accent); }
.card.warnrail .rail { background: var(--fail); }

/* panels + grid */
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin: 8px 0 26px; }
@media (max-width: 780px) { .grid { grid-template-columns: 1fr; } }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 20px;
  box-shadow: var(--shadow); }
.panel h2 { font-size: 14px; font-family: var(--mono); font-weight: 600; letter-spacing: .04em;
  text-transform: uppercase; color: var(--muted); margin-bottom: 16px; }
.panel h2 .hint { text-transform: none; letter-spacing: 0; color: var(--faint); font-weight: 500; }

/* bar rows */
.rows { display: flex; flex-direction: column; gap: 10px; }
.row { display: grid; grid-template-columns: 118px 1fr 46px; align-items: center; gap: 12px; font-size: 13px; }
.row .lbl { color: var(--ink); font-family: var(--mono); font-size: 12px; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; }
.row .track { height: 9px; background: var(--panel-2); border-radius: 6px; overflow: hidden; }
.row .fill { height: 100%; border-radius: 6px; background: var(--accent); transition: width .6s cubic-bezier(.2,.8,.2,1); }
.row .n { text-align: right; font-family: var(--mono); font-variant-numeric: tabular-nums; color: var(--muted); }
.sw { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 7px; vertical-align: middle; }

/* source table */
.stab { width: 100%; border-collapse: collapse; font-size: 13px; }
.stab th { text-align: right; font-family: var(--mono); font-weight: 500; font-size: 11px; letter-spacing: .04em;
  text-transform: uppercase; color: var(--faint); padding: 0 0 10px; border-bottom: 1px solid var(--line); }
.stab th:first-child, .stab td:first-child { text-align: left; }
.stab td { padding: 11px 0; border-bottom: 1px solid var(--line); font-variant-numeric: tabular-nums; }
.stab tr:last-child td { border-bottom: 0; }
.stab .src { font-family: var(--mono); font-weight: 600; color: var(--ink); }
.stab .desc { color: var(--faint); font-size: 11.5px; font-family: var(--sans); }
.pr { display: inline-block; min-width: 46px; text-align: center; padding: 2px 8px; border-radius: 6px;
  font-family: var(--mono); font-size: 12px; }

/* explorer */
.explorer { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; box-shadow: var(--shadow);
  overflow: hidden; }
.toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 16px 18px;
  border-bottom: 1px solid var(--line); }
.search { flex: 1; min-width: 190px; display: flex; align-items: center; gap: 8px; background: var(--bg);
  border: 1px solid var(--line); border-radius: 9px; padding: 8px 11px; }
.search input { border: 0; background: transparent; color: var(--ink); font: inherit; width: 100%; outline: none;
  font-family: var(--mono); font-size: 13px; }
.search svg { color: var(--faint); flex: none; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { font-family: var(--mono); font-size: 12px; color: var(--muted); background: var(--bg);
  border: 1px solid var(--line); border-radius: 999px; padding: 6px 12px; cursor: pointer; user-select: none; }
.chip[aria-pressed="true"] { color: var(--bg); background: var(--accent); border-color: var(--accent); }
.chip.fail[aria-pressed="true"] { background: var(--fail); border-color: var(--fail); color: #fff; }
select.sort { font-family: var(--mono); font-size: 12px; color: var(--ink); background: var(--bg);
  border: 1px solid var(--line); border-radius: 9px; padding: 8px 10px; cursor: pointer; }

.tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.tbl thead th { position: sticky; top: 0; background: var(--panel-2); text-align: right; font-family: var(--mono);
  font-weight: 500; font-size: 11px; letter-spacing: .03em; text-transform: uppercase; color: var(--muted);
  padding: 10px 14px; border-bottom: 1px solid var(--line); white-space: nowrap; }
.tbl thead th.l { text-align: left; }
.tbl thead th.s { cursor: pointer; }
.tbl thead th.s:hover { color: var(--ink); }
.tbl tbody td { padding: 11px 14px; border-bottom: 1px solid var(--line); vertical-align: middle;
  font-variant-numeric: tabular-nums; text-align: right; }
.tbl tbody td.l { text-align: left; }
.trow { cursor: pointer; }
.trow:hover td { background: var(--accent-soft); }
.slug { font-family: var(--mono); font-size: 12.5px; color: var(--ink); display: flex; align-items: center; gap: 9px; }
.slug .exp { color: var(--faint); transition: transform .18s; flex: none; }
.trow.open .slug .exp { transform: rotate(90deg); color: var(--accent); }
.srcbadge { font-family: var(--mono); font-size: 10.5px; padding: 2px 7px; border-radius: 5px; color: var(--muted);
  background: var(--panel-2); border: 1px solid var(--line); }
.pill { font-family: var(--mono); font-size: 11px; padding: 2px 9px; border-radius: 999px; font-weight: 600; }
.pill.pass { color: var(--pass); background: color-mix(in srgb, var(--pass) 15%, transparent); }
.pill.fail { color: var(--fail); background: color-mix(in srgb, var(--fail) 16%, transparent); }
.pill.warn { color: var(--warn); background: color-mix(in srgb, var(--warn) 16%, transparent); }
.risk { font-family: var(--mono); font-weight: 650; }
.tier { font-family: var(--mono); font-size: 10.5px; color: var(--muted); }
.sevdots { display: inline-flex; gap: 5px; justify-content: flex-end; }
.sevdot { font-family: var(--mono); font-size: 11px; padding: 1px 6px; border-radius: 5px; font-weight: 600; }
.sevdot.c { color: #fff; background: var(--crit); }
.sevdot.h { color: #fff; background: var(--high); }
.sevdot.m { color: #1a1200; background: var(--med); }
.sevdot.l { color: #fff; background: var(--low); }
.sevdot.z { color: var(--faint); }

.detail td { background: var(--panel-2); padding: 0 14px; border-bottom: 1px solid var(--line); }
.detail .inner { padding: 6px 0 14px; display: flex; flex-direction: column; gap: 8px; }
.finding { display: grid; grid-template-columns: 84px auto 1fr; gap: 12px; align-items: baseline;
  padding: 8px 12px; background: var(--panel); border: 1px solid var(--line); border-radius: 9px; }
@media (max-width: 640px) { .finding { grid-template-columns: 1fr; gap: 4px; } }
.finding .rid { font-family: var(--mono); font-size: 11px; font-weight: 600; }
.finding .ft { font-size: 12.5px; color: var(--ink); }
.finding .loc { font-family: var(--mono); font-size: 11px; color: var(--faint); }
.finding .ex { grid-column: 1 / -1; font-family: var(--mono); font-size: 11.5px; color: var(--muted);
  background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 6px 9px;
  overflow-x: auto; white-space: pre; }
.sev-c { color: var(--crit); } .sev-h { color: var(--high); } .sev-m { color: var(--med); }
.sev-l { color: var(--low); } .sev-i { color: var(--info); }
.empty { padding: 40px; text-align: center; color: var(--faint); font-family: var(--mono); font-size: 13px; }
.count { padding: 12px 18px; font-family: var(--mono); font-size: 12px; color: var(--faint);
  border-top: 1px solid var(--line); }

footer { margin-top: 34px; color: var(--muted); font-size: 13px; }
footer h2 { font-size: 13px; font-family: var(--mono); text-transform: uppercase; letter-spacing: .05em;
  color: var(--muted); margin-bottom: 10px; }
footer ul { margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: 6px; }
footer .note { max-width: 74ch; }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>

<header>
  <div class="head-in">
    <div class="brand"><span class="dot"></span>skill-guard <small>corpus eval</small></div>
    <span class="spacer"></span>
    <button class="toggle" id="themeBtn" type="button">theme</button>
  </div>
</header>

<div class="wrap">
  <section class="hero">
    <div class="eyebrow">OWASP Agentic Skills Top 10 · static scan</div>
    <h1 id="h1">Corpus Security Evaluation</h1>
    <p id="lede"></p>
  </section>

  <section class="cards" id="cards"></section>

  <div class="grid">
    <div class="panel"><h2>Findings by severity</h2><div class="rows" id="sevChart"></div></div>
    <div class="panel"><h2>Risk tiers <span class="hint">L0 clean · L1 low · L2 elevated · L3 high</span></h2><div class="rows" id="tierChart"></div></div>
  </div>
  <div class="grid">
    <div class="panel"><h2>Most-triggered rules</h2><div class="rows" id="ruleChart"></div></div>
    <div class="panel"><h2>OWASP AST coverage</h2><div class="rows" id="astChart"></div></div>
  </div>

  <div class="panel" style="margin-bottom:26px"><h2>By corpus</h2>
    <div style="overflow-x:auto"><table class="stab" id="srcTable"></table></div>
  </div>

  <h2 style="font-family:var(--mono);font-size:14px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 12px">Per-skill explorer</h2>
  <div class="explorer">
    <div class="toolbar">
      <label class="search">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
        <input id="q" type="text" placeholder="search skill slug…" autocomplete="off" spellcheck="false">
      </label>
      <div class="chips" id="srcChips"></div>
      <div class="chips">
        <span class="chip fail" id="failOnly" role="button" tabindex="0" aria-pressed="false">fails only</span>
      </div>
      <select class="sort" id="sortSel">
        <option value="risk">sort: risk ↓</option>
        <option value="findings">sort: findings ↓</option>
        <option value="slug">sort: slug A→Z</option>
        <option value="source">sort: source</option>
      </select>
    </div>
    <div style="overflow-x:auto">
      <table class="tbl">
        <thead><tr>
          <th class="l">skill</th>
          <th class="l">source</th>
          <th>verdict</th>
          <th class="s" data-sort="risk">risk</th>
          <th class="l">severity</th>
          <th class="s" data-sort="findings">findings</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
    <div class="count" id="count"></div>
  </div>

  <footer>
    <h2>Methodology &amp; caveats</h2>
    <ul class="note">
      <li>Built-in rulepacks only — no custom policy or waivers — so results reflect out-of-the-box behavior.</li>
      <li>Static analysis flags <strong>capability and pattern, not confirmed intent</strong>. A <em>pass</em> is not a safety guarantee; a <em>fail</em> is an invitation to review.</li>
      <li>These are real, <strong>unlabeled</strong> skills: an excellent false-positive corpus. Recall/true-positive coverage relies on the synthetic <span class="mono">testdata/malicious</span> fixtures, not shown here.</li>
      <li>Registry and repo contents drift; results reflect the fetch date in each corpus manifest.</li>
    </ul>
  </footer>
</div>

<script>
const DATA = __DATA__;
const $ = (s, r=document) => r.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h!=null) e.innerHTML = h; return e; };
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
const nf = n => (n||0).toLocaleString();
const SEV = [["critical","crit","var(--crit)"],["high","high","var(--high)"],["medium","med","var(--med)"],["low","low","var(--low)"],["info","info","var(--info)"]];
const SEVCLASS = {critical:"sev-c",high:"sev-h",medium:"sev-m",low:"sev-l",info:"sev-i"};

/* headline */
const V = DATA.verdicts||{}, ST = DATA.severity_totals||{};
const total = DATA.total_skills||0, npass = V.pass||0, nfail = V.fail||0, nwarn = V.warn||0;
const totFind = Object.values(ST).reduce((a,b)=>a+b,0);
const nSources = Object.keys(DATA.by_source||{}).length;
$("#h1").textContent = "Corpus Security Evaluation";
$("#lede").innerHTML = `Static scan of <strong>${nf(total)} real Agent Skills</strong> across ${nSources} sources against the skill-guard ruleset. `
  + `${nf(DATA.clean_skills||0)} produced zero findings; ${nf(totFind)} findings surfaced in total.`;

const cards = [
  {k:"skills scanned", v:nf(total), sub:`${nSources} corpus sources`},
  {k:"pass", v:nf(npass), sub:`${(100*npass/(total||1)).toFixed(1)}% of corpus`},
  {k:"fail", v:nf(nfail), sub:`${(100*nfail/(total||1)).toFixed(1)}% flagged for review`, warn:nfail>0},
  {k:"clean (0 findings)", v:nf(DATA.clean_skills||0), sub:`${(100*(DATA.clean_skills||0)/(total||1)).toFixed(1)}% no signal`},
  {k:"findings", v:nf(totFind), sub:`crit ${ST.critical||0} · high ${ST.high||0} · med ${ST.medium||0} · low ${ST.low||0}`},
];
const cw = $("#cards");
cards.forEach(c => { const d = el("div","card"+(c.warn?" warnrail":""));
  d.innerHTML = `<span class="rail"></span><div class="k">${c.k}</div><div class="v num">${c.v}</div><div class="sub">${c.sub}</div>`; cw.appendChild(d); });

/* bar chart helper */
function barChart(node, items, max, color) {
  const mx = max || Math.max(1, ...items.map(i=>i.n));
  items.forEach(i => {
    const r = el("div","row");
    r.innerHTML = `<span class="lbl" title="${esc(i.label)}">${i.swatch?`<span class="sw" style="background:${i.swatch}"></span>`:""}${esc(i.label)}</span>`
      + `<span class="track"><span class="fill" style="width:${i.n?Math.max(2,100*i.n/mx):0}%;${i.swatch?`background:${i.swatch}`:(color?`background:${color}`:"")}"></span></span>`
      + `<span class="n">${nf(i.n)}</span>`;
    node.appendChild(r);
  });
}
barChart($("#sevChart"), SEV.map(([k,,c])=>({label:k, n:ST[k]||0, swatch:c})));
const tiers = DATA.risk_tiers||{}; const tierMeta = {L0:"clean",L1:"low",L2:"elevated",L3:"high-risk"};
barChart($("#tierChart"), ["L0","L1","L2","L3"].filter(t=>t in tiers).map(t=>({label:`${t} ${tierMeta[t]||""}`, n:tiers[t]})), null, "var(--accent)");
const rh = DATA.rule_hits||{}, rt = DATA.rule_titles||{};
barChart($("#ruleChart"), Object.entries(rh).sort((a,b)=>b[1]-a[1]).slice(0,12).map(([id,n])=>({label:id, n})), null, "var(--accent)");
const ah = DATA.ast_hits||{};
barChart($("#astChart"), Object.entries(ah).sort((a,b)=>b[1]-a[1]).map(([id,n])=>({label:id, n})), null, "var(--accent)");

/* by-source table */
const stab = $("#srcTable");
stab.innerHTML = `<thead><tr><th>corpus</th><th>skills</th><th>pass rate</th><th>findings</th><th>avg risk</th><th>crit</th><th>high</th><th>med</th></tr></thead>`;
const tb = el("tbody");
Object.entries(DATA.by_source).sort((a,b)=>b[1].n-a[1].n).forEach(([src,s])=>{
  const sv = s.severity||{};
  const pr = s.pass_rate;
  const col = pr>=90?"var(--pass)":pr>=70?"var(--warn)":"var(--fail)";
  const desc = ({"clawhub":"ClawHub registry — top downloads","skillsmp":"SkillsMP — GitHub-indexed","orgs":"vendor repos (trailofbits, stripe…)","anthropic":"anthropics/skills examples","clawhub_more":"ClawHub extra batch","skillject":"SkillJect — malicious-skill research carriers"})[src]||"skill bundles";
  const tr = el("tr");
  tr.innerHTML = `<td class="l"><span class="src">${esc(src)}</span><br><span class="desc">${esc(desc)}</span></td>`
    + `<td class="num">${nf(s.n)}</td>`
    + `<td><span class="pr" style="color:${col};background:color-mix(in srgb, ${col} 14%, transparent)">${pr}%</span></td>`
    + `<td class="num">${nf(s.total_findings)}</td><td class="num">${s.avg_risk}</td>`
    + `<td class="num sev-c">${sv.critical||0}</td><td class="num sev-h">${sv.high||0}</td><td class="num sev-m">${sv.medium||0}</td>`;
  tb.appendChild(tr);
});
stab.appendChild(tb);

/* explorer */
const skills = (DATA.skills||[]).map((s,i)=>({...s, _i:i}));
const state = { q:"", sources:new Set(), failOnly:false, sort:"risk" };
const srcChips = $("#srcChips");
Object.keys(DATA.by_source).sort().forEach(src=>{
  const c = el("span","chip"); c.textContent = src; c.setAttribute("role","button"); c.tabIndex=0;
  c.setAttribute("aria-pressed","false");
  const toggle=()=>{ if(state.sources.has(src)){state.sources.delete(src);c.setAttribute("aria-pressed","false");}
    else{state.sources.add(src);c.setAttribute("aria-pressed","true");} render(); };
  c.onclick=toggle; c.onkeydown=e=>{ if(e.key==="Enter"||e.key===" "){e.preventDefault();toggle();} };
  srcChips.appendChild(c);
});
const failChip = $("#failOnly");
const failToggle=()=>{ state.failOnly=!state.failOnly; failChip.setAttribute("aria-pressed",state.failOnly); render(); };
failChip.onclick=failToggle; failChip.onkeydown=e=>{ if(e.key==="Enter"||e.key===" "){e.preventDefault();failToggle();} };
$("#q").oninput = e => { state.q = e.target.value.trim().toLowerCase(); render(); };
$("#sortSel").onchange = e => { state.sort = e.target.value; render(); };
document.querySelectorAll(".tbl thead th.s").forEach(th=>{
  th.onclick = () => { state.sort = th.dataset.sort; $("#sortSel").value = th.dataset.sort; render(); };
});

const SORTS = {
  risk: (a,b)=> b.risk_score-a.risk_score || b.n_findings-a.n_findings || a.slug.localeCompare(b.slug),
  findings: (a,b)=> b.n_findings-a.n_findings || b.risk_score-a.risk_score,
  slug: (a,b)=> a.slug.localeCompare(b.slug),
  source: (a,b)=> a.source.localeCompare(b.source) || b.risk_score-a.risk_score,
};
const tbody = $("#tbody");
function sevCell(c){
  const parts=[["c","critical"],["h","high"],["m","medium"],["l","low"]].map(([k,full])=>{
    const n=c[full]||0; return n?`<span class="sevdot ${k}">${n}</span>`:"";
  }).filter(Boolean).join("");
  return parts || `<span class="sevdot z">—</span>`;
}
function render(){
  let rows = skills.filter(s=>{
    if(state.q && !s.slug.toLowerCase().includes(state.q)) return false;
    if(state.sources.size && !state.sources.has(s.source)) return false;
    if(state.failOnly && s.verdict==="pass") return false;
    return true;
  }).sort(SORTS[state.sort]);
  tbody.innerHTML="";
  if(!rows.length){ tbody.innerHTML=`<tr><td colspan="6" class="empty">no skills match these filters</td></tr>`; $("#count").textContent="0 shown"; return; }
  const frag=document.createDocumentFragment();
  rows.forEach(s=>{
    const tr=el("tr","trow"); tr.dataset.i=s._i;
    const vc = s.verdict==="pass"?"pass":(s.verdict==="warn"?"warn":"fail");
    tr.innerHTML = `<td class="l"><span class="slug"><span class="exp">▸</span>${esc(s.slug)}</span></td>`
      + `<td class="l"><span class="srcbadge">${esc(s.source)}</span></td>`
      + `<td><span class="pill ${vc}">${esc(s.verdict)}</span></td>`
      + `<td><span class="risk">${s.risk_score}</span> <span class="tier">${esc(s.risk_tier)}</span></td>`
      + `<td><span class="sevdots">${sevCell(s.counts||{})}</span></td>`
      + `<td class="num">${s.n_findings}</td>`;
    tr.onclick=()=>toggleDetail(tr,s);
    frag.appendChild(tr);
  });
  tbody.appendChild(frag);
  $("#count").textContent = `${rows.length} of ${skills.length} skills shown`;
}
function toggleDetail(tr,s){
  const open = tr.classList.toggle("open");
  const next = tr.nextElementSibling;
  if(!open){ if(next && next.classList.contains("detail")) next.remove(); return; }
  const dtr=el("tr","detail"); const td=el("td"); td.colSpan=6;
  const inner=el("div","inner");
  if(!s.findings || !s.findings.length){ inner.innerHTML=`<div class="loc" style="font-family:var(--mono);color:var(--faint)">no findings — clean scan</div>`; }
  else s.findings.forEach(f=>{
    const sc = SEVCLASS[f.severity]||"sev-i";
    const fd=el("div","finding");
    const loc = f.file?`${esc(f.file)}:${f.line}`:"";
    const ast = (f.ast||[]).join(" ");
    fd.innerHTML = `<span class="rid ${sc}">${esc(f.rule_id)}</span>`
      + `<span class="ft">${esc(f.title)} <span class="loc">${ast?esc(ast)+" · ":""}${esc(f.severity)}</span></span>`
      + `<span class="loc">${esc(loc)}</span>`
      + (f.excerpt?`<span class="ex">${esc(f.excerpt)}</span>`:"");
    inner.appendChild(fd);
  });
  td.appendChild(inner); dtr.appendChild(td); tr.after(dtr);
}
render();

/* theme toggle */
const root = document.documentElement;
$("#themeBtn").onclick = () => {
  const cur = root.getAttribute("data-theme")
    || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  root.setAttribute("data-theme", cur==="dark"?"light":"dark");
};
</script>
"""


def main():
    stats = json.load(open(os.path.join(REPORTS, STATS_NAME)))
    html = TEMPLATE.replace("__TITLE__", TITLE).replace(
        "__DATA__", json.dumps(stats, separators=(",", ":")))
    out = os.path.join(REPORTS, HTML_NAME)
    with open(out, "w") as f:
        f.write(html)
    print(f"wrote {out}  ({len(html)//1024} KiB, {stats.get('total_skills')} skills)")


if __name__ == "__main__":
    main()
