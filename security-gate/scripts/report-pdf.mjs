#!/usr/bin/env node
// Builds an enterprise-style, priority-ranked PDF from the gate's report.json (layout modelled on a vulnerability-scan
// report: running header, summary, findings by severity and by category, a clickable issue index and ONE PAGE PER ISSUE).
// No npm dependencies: it writes a print-styled HTML file and prints it to PDF with the Edge/Chrome that is already
// installed (headless). Internal links survive as clickable PDF links. If no browser is found the HTML file is kept
// (open it and Print > Save as PDF).
//   node report-pdf.mjs <report.json> [out.pdf] [--project <name>]
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

// Priority levels: L0 = High (critical + high severity), L1 = Medium, L2 = Low.
export const PRIORITY = { critical: 'L0', high: 'L0', medium: 'L1', low: 'L2' };
export const priorityOf = (sev) => PRIORITY[sev] || 'L1';
const LEVELS = [
  { id: 'L0', name: 'High', when: 'Fix now, blocks release', color: '#b42318', soft: '#fef3f2' },
  { id: 'L1', name: 'Medium', when: 'Fix in the current sprint', color: '#b54708', soft: '#fffaeb' },
  { id: 'L2', name: 'Low', when: 'Track, fix when convenient', color: '#067647', soft: '#ecfdf3' },
];
const LEVEL = Object.fromEntries(LEVELS.map((l) => [l.id, l]));
const SEVERITIES = [
  { id: 'critical', name: 'Critical', color: '#7a0c10' }, { id: 'high', name: 'High', color: '#d92d20' },
  { id: 'medium', name: 'Medium', color: '#dc6803' }, { id: 'low', name: 'Low', color: '#079455' },
];
const SEV = { low: 1, medium: 2, high: 3, critical: 4 };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const STATUS = {
  PASS: ['Passed', 'ok'], FAIL: ['Blocking findings', 'bad'], 'NOT-RUN': ['Not run', 'warn'], ERROR: ['Tool error', 'warn'],
  'NO-COVERAGE': ['Nothing to scan', 'warn'], 'N/A': ['Not applicable', 'mut'],
};
const TOOL_LABEL = { gitleaks: 'gitleaks', nuget: 'NuGet Audit', semgrep: 'Semgrep', osv: 'OSV-Scanner', grype: 'Grype', trivy: 'Trivy', zap: 'OWASP ZAP' };
const CATEGORY = { gitleaks: 'Credential leaks', nuget: 'Software composition (SCA)', osv: 'Software composition (SCA)', semgrep: 'Static analysis (SAST)', trivy: 'Containers, IaC and dependencies', grype: 'Containers, IaC and dependencies', zap: 'Dynamic analysis (DAST)' };
const CATEGORY_ORDER = ['Credential leaks', 'Software composition (SCA)', 'Static analysis (SAST)', 'Containers, IaC and dependencies', 'Dynamic analysis (DAST)'];
const WHAT = {
  gitleaks: 'A value that looks like a credential (API key, token, password) was found in a file. If it is real it is compromised, because anyone with access to the repository or its history can use it. Some matches are identifiers (for example GUIDs) that only look like keys.',
  nuget: 'A NuGet package used by the solution has a publicly known vulnerability (advisory). Direct and transitive dependencies are checked.',
  osv: 'A dependency has a publicly known vulnerability recorded in the OSV database.',
  grype: 'A package or runtime file has a publicly known vulnerability (CVE/GHSA) according to the Grype database.',
  trivy: 'Trivy found a known vulnerable dependency, an insecure Dockerfile / infrastructure-as-code setting, or an exposed secret.',
  semgrep: 'Semgrep matched a rule for an insecure code pattern (static analysis).',
  zap: 'OWASP ZAP observed a weakness while crawling the running web application.',
};
const MAX_PAGES = 150; // issue pages; any further issues are listed in the index and in report.json
const ITEM_ROWS = 12; // affected items shown on an issue page (the rest are in report.json)

function action(f) {
  if (f.tool === 'gitleaks' && /guid-like/i.test(f.title || '')) return 'Probable false positive: the line only holds a GUID (an identifier, not a password). Open one hit to confirm, then suppress this rule id with a reason and expiry.';
  if (/probable false positive/i.test(f.title || '')) return 'Probable false positive: the version looks like an assembly version (x.y.z.0). Confirm the real package version with NuGet audit, then suppress with a reason and expiry.';
  if (f.tool === 'gitleaks') return 'Rotate the credential first, then remove it from code and history and load it from env or Key Vault. If the match is only an identifier, suppress it with a reason and expiry.';
  if (f.tool === 'semgrep') return 'Fix the flagged code (see rule id). If it is a false positive, suppress with a reason and expiry.';
  if (f.tool === 'zap') return f.solution ? `Fix the web issue: ${f.solution}` : 'Fix the web issue reported by ZAP (see alert); re-run the DAST scan to confirm.';
  if (/\[misconfiguration\]/i.test(f.title || '')) return 'Fix the IaC / Dockerfile setting named in the rule id (see Trivy advisory), then re-run.';
  if (/\[secret\]/i.test(f.title || '')) return 'Rotate the credential first, then remove it from code and load it from env or Key Vault.';
  const name = String(f.package || '').split('@')[0];
  const to = f.fixed ? `Upgrade ${name} to ${f.fixed}.` : `Upgrade ${name} to a patched version (see advisory).`;
  return /transitive/i.test(f.title || '') ? `${to} Transitive: pin the newer version directly (Directory.Packages.props).` : to;
}
const chip = (text, kind) => `<span class="chip ${kind}">${esc(text)}</span>`;
const sevTag = (sev, known = true) => `<span class="sev s-${esc(sev)}">${esc(sev)}${known ? '' : '?'}</span>`;
const titleOf = (f) => String(f.title || '').replace(/^\[[^\]]+\]\s*/, '') || f.id;

export function buildHtml(rep, project) {
  const failOn = rep.failOn || 'high';
  const all = [];
  for (const t of rep.tools) for (const f of t.findings) all.push({ ...f, blocking: SEV[f.severity] >= SEV[failOn] });
  const counts = Object.fromEntries(LEVELS.map((l) => [l.id, all.filter((f) => priorityOf(f.severity) === l.id).length]));
  const sevCounts = Object.fromEntries(SEVERITIES.map((s) => [s.id, all.filter((f) => f.severity === s.id).length]));
  const total = all.length; const blockers = all.filter((f) => f.blocking).length;
  const vcolor = { PASS: '#067647', FAIL: '#b42318', INCOMPLETE: '#b54708' }[rep.verdict] || '#475467';
  const notOk = rep.tools.filter((t) => !['PASS', 'FAIL', 'N/A'].includes(t.final));
  const date = String(rep.generated || '').replace('T', ' ').slice(0, 16) + ' UTC';
  const dateShort = String(rep.generated || '').slice(0, 10);
  const partial = (rep.notes || []).find((n) => /^Partial scan/i.test(n));

  // ---- issues: grouped by tool + id, numbered 1..N from the most severe down
  const issueMap = new Map();
  for (const f of all) {
    const key = `${f.tool}|${f.id}`;
    const g = issueMap.get(key) || { tool: f.tool, id: f.id, sevN: 0, severity: f.severity, known: f.severityKnown, items: [], fixed: new Set(), sample: f };
    g.items.push(f); if (f.fixed) g.fixed.add(f.fixed); if (SEV[f.severity] > g.sevN) { g.sevN = SEV[f.severity]; g.severity = f.severity; g.sample = f; }
    issueMap.set(key, g);
  }
  const issues = [...issueMap.values()].sort((a, b) => b.sevN - a.sevN || b.items.length - a.items.length || String(a.id).localeCompare(String(b.id)));
  issues.forEach((g, i) => { g.no = i + 1; g.detailed = g.no <= MAX_PAGES; });
  const noOf = new Map(issues.map((g) => [`${g.tool}|${g.id}`, g]));
  const jump = (g, inner) => (g && g.detailed ? `<a class="lnk" href="#issue-${g.no}">${inner}</a>` : inner);

  // ---- key points
  const points = [];
  points.push(blockers ? `<b>${blockers}</b> finding(s) in <b>${issues.filter((g) => g.items.some((f) => f.blocking)).length}</b> issue(s) reach the <b>${esc(failOn)}</b> threshold and block the release. Start with <b>L0</b>.` : `No finding reaches the <b>${esc(failOn)}</b> blocking threshold.`);
  if (notOk.length) points.push(`Coverage gap: ${notOk.map((t) => `<b>${esc(TOOL_LABEL[t.tool] || t.tool)}</b> (${esc((STATUS[t.final] || [t.final])[0].toLowerCase())})`).join(', ')}. The gate cannot be called clean until these run.`);
  if ((rep.skipped || []).length) points.push(`Skipped by request: ${rep.skipped.map(esc).join(', ')}.`);
  if (partial) points.push(esc(partial));
  if (all.some((f) => !f.severityKnown)) points.push('Findings marked <b>?</b> had no severity from the tool and are treated as Medium.');
  if (all.some((f) => f.tool !== 'gitleaks' && /probable false positive/i.test(f.title || ''))) points.push('Some dependency findings are <b>probable false positives</b> (assembly version read as package version). Verify with NuGet audit.');
  const guidHits = all.filter((f) => f.tool === 'gitleaks' && /guid-like/i.test(f.title || '')).length;
  if (guidHits) points.push(`<b>${guidHits}</b> secret hit(s) only contain a GUID and are ranked <b>Low</b> as probable false positives (identifiers, not passwords).`);
  points.push(`Every issue has its own numbered page (<b>1 to ${issues.length}</b>). Click a row in the <a class="lnk" href="#index">issue index</a> to jump to it.`);

  // ---- summary boxes + bars
  const box = (label, value, color, sub) => `<div class="sbox"><div class="sl">${label}</div><div class="sv" style="color:${color}">${value}</div><div class="ss">${sub}</div></div>`;
  const summary = [
    box('Security gate', esc(rep.verdict), vcolor, `fails on ${esc(failOn)} and above`),
    box('Issues', issues.length, '#0b1f3a', `${total} findings, ${blockers} blocking`),
    box('L0 &middot; High', counts.L0, LEVELS[0].color, 'critical + high'),
    box('L1 &middot; Medium', counts.L1, LEVELS[1].color, 'medium'),
    box('L2 &middot; Low', counts.L2, LEVELS[2].color, 'low'),
  ].join('');
  const maxSev = Math.max(1, ...Object.values(sevCounts));
  const bars = SEVERITIES.map((s) => `<div class="brow"><div class="bl">${s.name}</div><div class="bt"><i style="width:${(sevCounts[s.id] / maxSev) * 100}%;background:${s.color}"></i></div><div class="bn">${sevCounts[s.id]}</div></div>`).join('');

  // ---- by category
  const catRows = CATEGORY_ORDER.map((c) => {
    const tools = rep.tools.filter((t) => CATEGORY[t.tool] === c); if (!tools.length) return '';
    const fs_ = tools.flatMap((t) => t.findings);
    const cell = (id) => { const n = fs_.filter((f) => f.severity === id).length; return `<td class="num ${n ? 'nz' : ''}">${n}</td>`; };
    const states = tools.map((t) => `${esc(TOOL_LABEL[t.tool] || t.tool)}: ${esc((STATUS[t.final] || [t.final])[0].toLowerCase())}`).join('<br>');
    return `<tr><td><b>${esc(c)}</b></td>${SEVERITIES.map((s) => cell(s.id)).join('')}<td class="num"><b>${fs_.length}</b></td><td class="small mut">${states}</td></tr>`;
  }).join('');

  // ---- fix first (each row links to the first matching issue page)
  const groups = new Map();
  for (const f of all.filter((x) => SEV[x.severity] >= SEV.high)) {
    const key = `${f.tool}|${f.tool === 'gitleaks' || f.tool === 'semgrep' ? f.id : String(f.package).split('@')[0]}`;
    const g = groups.get(key) || { tool: f.tool, sev: 0, n: 0, ids: new Set(), sample: f };
    g.n++; g.ids.add(f.id); g.sev = Math.max(g.sev, SEV[f.severity]); groups.set(key, g);
  }
  const fixFirst = [...groups.values()].sort((a, b) => b.sev - a.sev || b.n - a.n).slice(0, 8);
  const fixRows = fixFirst.map((g, i) => {
    const first = noOf.get(`${g.tool}|${[...g.ids][0]}`);
    return `<tr><td class="num">${i + 1}</td><td>${esc(action(g.sample))}</td><td>${esc(TOOL_LABEL[g.tool] || g.tool)}</td><td class="id">${[...g.ids].slice(0, 2).map((id) => jump(noOf.get(`${g.tool}|${id}`), esc(id))).join('<br>')}${g.ids.size > 2 ? `<br><span class="mut">+${g.ids.size - 2} more</span>` : ''}</td><td class="num">${g.n}</td><td class="num">${first ? jump(first, `<span class="nb" style="background:${LEVEL[priorityOf(first.severity)].color}">${first.no}</span>`) : ''}</td></tr>`;
  }).join('');

  // ---- scan details
  const toolRows = rep.tools.map((t) => {
    const [label, kind] = STATUS[t.final] || [t.final, 'warn'];
    return `<tr><td><b>${esc(TOOL_LABEL[t.tool] || t.tool)}</b><br><span class="mut small">${esc(CATEGORY[t.tool] || '')}</span></td><td>${chip(label, kind)}</td><td class="num">${t.findings.length}</td><td class="small mut">${esc(t.version || '')}</td><td class="small mut">${esc(t.note || '')}</td></tr>`;
  }).join('');

  // ---- clickable issue index
  const indexRows = issues.map((g) => {
    const lv = LEVEL[priorityOf(g.severity)];
    return `<tr><td class="num">${jump(g, `<span class="nb" style="background:${lv.color}">${g.no}</span>`)}</td><td><b style="color:${lv.color}">${lv.id}</b></td><td>${sevTag(g.severity, g.known)}</td><td>${esc(TOOL_LABEL[g.tool] || g.tool)}</td><td class="id">${jump(g, esc(g.id))}</td><td class="small">${jump(g, esc(titleOf(g.sample).slice(0, 90)))}</td><td class="num">${g.items.length}</td></tr>`;
  }).join('');

  // ---- one page per issue
  const page = (g) => {
    const f = g.sample; const lv = LEVEL[priorityOf(g.severity)];
    const itemRows = g.items.slice(0, ITEM_ROWS).map((it, i) => `<tr><td class="num">${i + 1}</td><td>${esc(it.package || '-')}</td><td class="small">${esc(it.location)}</td></tr>`).join('');
    const more = g.items.length > ITEM_ROWS ? `<tr><td></td><td colspan="2" class="mut small">+ ${g.items.length - ITEM_ROWS} more items in report.json</td></tr>` : '';
    const prev = g.no > 1 ? `<a class="lnk" href="#issue-${g.no - 1}">&larr; Issue ${g.no - 1}</a>` : '';
    const next = g.no < Math.min(issues.length, MAX_PAGES) ? `<a class="lnk" href="#issue-${g.no + 1}">Issue ${g.no + 1} &rarr;</a>` : '';
    return `<section class="issue" id="issue-${g.no}">
      <div class="ihead" style="--c:${lv.color};--s:${lv.soft}"><div class="ino">${g.no}</div><div class="itxt"><div class="ilab">Issue ${g.no} of ${issues.length} &nbsp;&middot;&nbsp; ${lv.id} ${lv.name} priority &nbsp;&middot;&nbsp; ${esc(lv.when)}</div><h3>${esc(titleOf(f))}</h3></div></div>
      <table class="kv"><tr><th>Issue ID</th><td class="id">${esc(g.id)}</td><th>Severity</th><td>${sevTag(g.severity, g.known)} &nbsp;<b style="color:${lv.color}">${lv.id}</b></td></tr>
      <tr><th>Tool</th><td>${esc(TOOL_LABEL[g.tool] || g.tool)}</td><th>Category</th><td>${esc(CATEGORY[g.tool] || '')}</td></tr>
      <tr><th>Affected items</th><td>${g.items.length}</td><th>Fixed in</th><td>${g.fixed.size ? esc([...g.fixed].slice(0, 3).join(', ')) : '-'}</td></tr></table>
      <h4>What this means</h4><p>${esc(WHAT[g.tool] || '')}</p>
      <h4>Solution</h4><p>${esc(action(f))}</p>
      <h4>Affected items</h4><table class="items"><thead><tr><th>#</th><th>Package</th><th>Location</th></tr></thead><tbody>${itemRows}${more}</tbody></table>
      <div class="nav"><a class="lnk" href="#index">&uarr; Issue list</a><span>${prev}${prev && next ? ' &nbsp;|&nbsp; ' : ''}${next}</span></div></section>`;
  };
  const undetailed = issues.filter((g) => !g.detailed).length;

  const suppressed = rep.tools.flatMap((t) => (t.suppressedFindings || []).map((f) => `<li><b>${esc(t.tool)}</b> ${esc(f.id)} ${esc(f.package)} &mdash; ${esc(f.suppressedBy)} <span class="mut">(until ${esc(f.until)})</span></li>`));
  const invalid = (rep.invalidSuppressions || []).map((e) => `<li>${esc(e.id || '(no id)')}: ${esc(e.why)}</li>`);
  const notes = (rep.notes || []).filter((n) => !/^Partial scan/i.test(n)).map((n) => `<li>${esc(n)}</li>`);
  const pn = esc(project).replace(/"/g, '');

  return `<!doctype html><html><head><meta charset="utf-8"><title>Security Gate Scan Report - ${esc(project)}</title><style>
  @page { size: A4; margin: 21mm 14mm 18mm;
    @top-left { content: "Security Gate Scan Report"; font: 700 8.5pt Arial, Helvetica, sans-serif; color: #0b1f3a; }
    @top-right { content: "CONFIDENTIAL  |  ${pn}"; font: 8pt Arial, Helvetica, sans-serif; color: #667085; }
    @bottom-left { content: "Secret values are never included in this report."; font: 7.5pt Arial, Helvetica, sans-serif; color: #98a2b3; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt Arial, Helvetica, sans-serif; color: #667085; } }
  * { box-sizing: border-box; } html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { font: 9.6pt/1.45 Arial, Helvetica, "Segoe UI", sans-serif; color: #101828; margin: 0; }
  a.lnk, a.lnk:visited { color: #1d4ed8; text-decoration: none; font-weight: 600; } a.lnk:hover { text-decoration: underline; }
  .nb { display: inline-block; min-width: 27pt; padding: 2.5pt 7pt; border-radius: 13pt; color: #fff; font-weight: 700; font-size: 9.5pt; text-align: center; line-height: 1.15; }
  table.idx th, table.idx td { padding: 4pt 5pt; } table.idx td.num:first-child, table.idx th:first-child { width: 44pt; text-align: center; }
  table.idx td:nth-child(2) { width: 38pt; } table.idx td:nth-child(3) { width: 56pt; } table.idx td:nth-child(4) { width: 62pt; white-space: nowrap; }
  table.idx td.id { width: 122pt; white-space: nowrap; word-break: normal; font-size: 7.8pt; } table.idx td:last-child { width: 32pt; }
  table.idx a.lnk { font-weight: 400; } table.idx td.num a.lnk { font-weight: 700; } table.idx tr { page-break-inside: avoid; }
  .mut { color: #667085; } .small { font-size: 8.4pt; } .num { text-align: center; width: 26pt; color: #475467; } td.nz { font-weight: 700; color: #101828; }
  h1 { font-size: 24pt; margin: 0; color: #0b1f3a; letter-spacing: -.3pt; } .sub { color: #475467; font-size: 11pt; margin: 3pt 0 0; }
  .titlebar { border-top: 5pt solid #0b1f3a; padding-top: 10pt; margin-bottom: 6pt; }
  .conf { margin-top: 8pt; padding: 6pt 9pt; background: #f2f4f7; border-left: 3pt solid #667085; font-size: 8pt; color: #475467; }
  h2 { font-size: 12.5pt; margin: 17pt 0 6pt; color: #0b1f3a; padding-bottom: 3pt; border-bottom: 1.5pt solid #0b1f3a; page-break-after: avoid; }
  h3 { font-size: 13pt; margin: 2pt 0 0; color: #101828; line-height: 1.25; } h4 { font-size: 8.6pt; text-transform: uppercase; letter-spacing: .6pt; color: #475467; margin: 11pt 0 3pt; }
  p { margin: 0 0 4pt; }
  .meta { width: 100%; margin-top: 6pt; } .meta th { width: 112pt; text-align: left; color: #475467; font-weight: 600; background: none; text-transform: none; letter-spacing: 0; font-size: 9pt; border: 0; padding: 3pt 0; }
  .meta td { border: 0; padding: 3pt 0; background: none !important; }
  .summary { display: flex; gap: 8pt; margin: 8pt 0 4pt; } .sbox { flex: 1; border: 0.8pt solid #d0d5dd; border-top: 3pt solid #0b1f3a; border-radius: 3pt; padding: 8pt 9pt; text-align: center; }
  .sl { font-size: 7.8pt; text-transform: uppercase; letter-spacing: .6pt; color: #475467; } .sv { font-size: 21pt; font-weight: 700; line-height: 1.15; margin: 3pt 0 1pt; } .ss { font-size: 7.6pt; color: #667085; }
  .brow { display: flex; align-items: center; gap: 8pt; margin: 4pt 0; } .bl { width: 52pt; font-size: 9pt; } .bt { flex: 1; height: 10pt; background: #f2f4f7; border-radius: 2pt; overflow: hidden; } .bt i { display: block; height: 100%; } .bn { width: 30pt; font-weight: 700; text-align: right; }
  ul.pts { margin: 4pt 0 0 14pt; padding: 0; } ul.pts li { margin: 3pt 0; } ul.plain { margin: 4pt 0 0 14pt; padding: 0; font-size: 8.8pt; } ul.plain li { margin: 2pt 0; }
  table { width: 100%; border-collapse: collapse; margin-top: 4pt; } th { text-align: left; font-size: 8pt; text-transform: uppercase; letter-spacing: .5pt; color: #fff; background: #0b1f3a; }
  th, td { padding: 4.5pt 6pt; vertical-align: top; } td { border-bottom: 0.6pt solid #e4e7ec; } tbody tr:nth-child(even) td { background: #fafbfc; } tr { page-break-inside: avoid; }
  td.id { font: 8.2pt Consolas, "Courier New", monospace; word-break: break-all; min-width: 70pt; }
  .chip { display: inline-block; padding: 1.5pt 8pt; border-radius: 10pt; font-size: 8pt; font-weight: 700; white-space: nowrap; }
  .chip.ok { background: #d1fadf; color: #05603a; } .chip.bad { background: #fee4e2; color: #912018; } .chip.warn { background: #fef0c7; color: #93370d; } .chip.mut { background: #eaecf0; color: #344054; }
  .sev { display: inline-block; padding: 1pt 7pt; border-radius: 3pt; font-size: 7.8pt; font-weight: 700; text-transform: uppercase; color: #fff; background: #667085; }
  .s-critical { background: #7a0c10; } .s-high { background: #d92d20; } .s-medium { background: #dc6803; } .s-low { background: #079455; }
  section.issue { break-before: page; page-break-before: always; }
  .ihead { display: flex; gap: 14pt; align-items: center; background: var(--s); border-left: 6pt solid var(--c); border-radius: 4pt; padding: 12pt 14pt; margin-bottom: 12pt; }
  .ino { min-width: 52pt; height: 52pt; line-height: 52pt; text-align: center; border-radius: 50%; background: var(--c); color: #fff; font-size: 24pt; font-weight: 700; }
  .ilab { font-size: 8.4pt; color: #475467; text-transform: uppercase; letter-spacing: .5pt; font-weight: 700; }
  table.kv { margin: 0 0 2pt; } table.kv th { width: 78pt; background: #f2f4f7; color: #344054; border-bottom: 0.6pt solid #e4e7ec; text-transform: none; font-size: 8.4pt; letter-spacing: 0; }
  table.kv td { background: #fff !important; } table.items th { background: #475467; }
  .nav { margin-top: 14pt; padding-top: 7pt; border-top: 0.6pt solid #d0d5dd; display: flex; justify-content: space-between; font-size: 9pt; }
  .legend td { font-size: 8.8pt; }
  .foot { margin-top: 16pt; padding-top: 7pt; border-top: 0.6pt solid #d0d5dd; color: #667085; font-size: 8pt; }
  </style></head><body>
  <div class="titlebar"><h1>Security Gate Scan Report</h1><p class="sub">Scan report ${esc(dateShort)} &nbsp;&middot;&nbsp; ${esc(project)}</p></div>
  <table class="meta">
    <tr><th>Project</th><td><b>${esc(project)}</b></td></tr>
    <tr><th>Scan date</th><td>${esc(date)}</td></tr>
    <tr><th>Checks run</th><td>${esc(rep.tools.map((t) => TOOL_LABEL[t.tool] || t.tool).join(', '))}</td></tr>
    <tr><th>Blocking threshold</th><td>${esc(failOn)} severity and above (a finding at or above this fails the gate)</td></tr>
    ${partial ? `<tr><th>Scope</th><td>${esc(partial)}</td></tr>` : ''}
  </table>
  <div class="conf"><b>CONFIDENTIAL.</b> This report lists internal file paths and package names. Scanners report known issues only; a pass is not a penetration test. Secret values are never included.</div>

  <h2>Summary</h2>
  <div class="summary">${summary}</div>
  <ul class="pts">${points.map((p) => `<li>${p}</li>`).join('')}</ul>

  <h2>Findings by severity</h2>
  ${bars}

  <h2>Findings by category</h2>
  <table><thead><tr><th>Category</th><th class="num" style="color:#fff">Critical</th><th class="num" style="color:#fff">High</th><th class="num" style="color:#fff">Medium</th><th class="num" style="color:#fff">Low</th><th class="num" style="color:#fff">Total</th><th>Status</th></tr></thead><tbody>${catRows}</tbody></table>

  ${fixFirst.length ? `<h2>Fix first</h2><table><thead><tr><th>#</th><th>What to do</th><th>Tool</th><th>Advisory / rule (click)</th><th>Items</th><th>Issue</th></tr></thead><tbody>${fixRows}</tbody></table>` : ''}

  <h2>Scan details</h2>
  <table><thead><tr><th>Check</th><th>Status</th><th>Findings</th><th>Version / image</th><th>Notes</th></tr></thead><tbody>${toolRows}</tbody></table>

  <h2 id="index" style="break-before: page; page-break-before: always;">Issue index (${issues.length} issue${issues.length === 1 ? '' : 's'}, ${total} finding${total === 1 ? '' : 's'})</h2>
  <p class="small mut">Numbered from the most severe. <b>Click a row</b> (number, ID or title) to open that issue's page; every issue page has a link back to this list.</p>
  ${issues.length ? `<table class="idx"><thead><tr><th>No.</th><th>Priority</th><th>Severity</th><th>Tool</th><th>ID</th><th>Issue</th><th>Items</th></tr></thead><tbody>${indexRows}</tbody></table>` : '<p class="mut">No issues found.</p>'}
  ${undetailed ? `<p class="small mut">${undetailed} lower-ranked issue(s) are listed above without a page; full details are in report.json.</p>` : ''}

  ${page_(issues, page)}

  <section style="break-before: page; page-break-before: always;">
  ${suppressed.length ? `<h2>Accepted risks (suppressed)</h2><ul class="plain">${suppressed.join('')}</ul>` : ''}
  ${invalid.length ? `<h2>Suppression entries ignored</h2><ul class="plain">${invalid.join('')}</ul>` : ''}
  ${notes.length ? `<h2>Run notes</h2><ul class="plain">${notes.join('')}</ul>` : ''}

  <h2>Appendix: how to read this report</h2>
  <table class="legend"><thead><tr><th>Priority</th><th>Severity covered</th><th>Meaning</th></tr></thead><tbody>
  <tr><td><b style="color:#b42318">L0 &middot; High</b></td><td>Critical, High</td><td>Fix now. Any secret leak is L0: rotate the credential first.</td></tr>
  <tr><td><b style="color:#b54708">L1 &middot; Medium</b></td><td>Medium, unknown severity</td><td>Fix in the current sprint.</td></tr>
  <tr><td><b style="color:#067647">L2 &middot; Low</b></td><td>Low, Negligible</td><td>Track and fix when convenient.</td></tr></tbody></table>
  <div class="foot">Scope: OSV-Scanner and NuGet Audit (SCA), Semgrep (SAST), gitleaks (secrets), Trivy and Grype (dependencies, IaC, images), OWASP ZAP (DAST, when run). Generated by Security Gate. <a class="lnk" href="#index">Back to the issue list</a></div>
  </section>
  </body></html>`;
}
// builds the issue pages (kept separate so the template above stays readable)
function page_(issues, page) { return issues.filter((g) => g.detailed).map(page).join(''); }

function findBrowser() {
  const c = [
    process.env.PDF_BROWSER,
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge',
  ].filter(Boolean);
  return c.find((p) => fs.existsSync(p)) || null;
}

export function buildPdf(jsonPath, pdfPath, project) {
  const rep = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const html = buildHtml(rep, project || path.basename(path.resolve(path.dirname(jsonPath), '..', '..')));
  const htmlPath = pdfPath.replace(/\.pdf$/i, '') + '.html';
  fs.writeFileSync(htmlPath, html);
  const browser = findBrowser();
  if (!browser) return { ok: false, file: htmlPath, note: 'No Edge/Chrome found; open the HTML and use Print > Save as PDF (or set PDF_BROWSER).' };
  const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-pdf-'));
  try {
    try { fs.rmSync(pdfPath, { force: true }); } catch { /* ignore */ }
    const r = spawnSync(browser, ['--headless', '--disable-gpu', '--no-pdf-header-footer', '--generate-pdf-document-outline', `--user-data-dir=${prof}`, `--print-to-pdf=${pdfPath}`, pathToFileURL(htmlPath).href], { encoding: 'utf8', timeout: 120000, windowsHide: true });
    if (!fs.existsSync(pdfPath)) return { ok: false, file: htmlPath, note: `PDF not produced (browser exit ${r.status}): ${String(r.stderr).slice(-200)}` };
    return { ok: true, file: pdfPath, html: htmlPath, note: '' };
  } finally { try { fs.rmSync(prof, { recursive: true, force: true }); } catch { /* ignore */ } }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const a = process.argv.slice(2); const pi = a.indexOf('--project');
  const project = pi >= 0 ? a.splice(pi, 2)[1] : '';
  if (!a[0]) { console.error('usage: node report-pdf.mjs <report.json> [out.pdf] [--project <name>]'); process.exit(2); }
  const json = path.resolve(a[0]); const out = path.resolve(a[1] || path.join(path.dirname(json), 'security-report.pdf'));
  const r = buildPdf(json, out, project);
  console.log(r.ok ? `PDF: ${r.file}` : `PDF not created: ${r.note}\nHTML: ${r.file}`);
  process.exit(r.ok ? 0 : 1);
}
