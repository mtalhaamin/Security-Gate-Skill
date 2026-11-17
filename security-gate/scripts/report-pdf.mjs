#!/usr/bin/env node
// Builds a priority-ranked PDF from the gate's report.json. No npm dependencies: it writes a print-styled HTML
// file and prints it to PDF with the Edge/Chrome that is already installed (headless). If none is found the
// HTML file is kept (open it and Print > Save as PDF).
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
  { id: 'L0', name: 'High', when: 'Fix now - blocks release', color: '#b42318', bg: '#fdecea' },
  { id: 'L1', name: 'Medium', when: 'Fix in the current sprint', color: '#b54708', bg: '#fff4e5' },
  { id: 'L2', name: 'Low', when: 'Fix when convenient / track', color: '#1d6f42', bg: '#e8f5ee' },
];
const SEV = { low: 1, medium: 2, high: 3, critical: 4 };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function action(f) {
  if (/probable false positive/i.test(f.title || '')) return 'Probable false positive: the version looks like an assembly version (x.y.z.0). Confirm the real package version with NuGet audit, then suppress with a reason and expiry.';
  if (f.tool === 'gitleaks') return 'Rotate the credential first, then remove it from code/history and load it from env or Key Vault.';
  if (f.tool === 'semgrep') return 'Fix the flagged code (see rule id); false positive: suppress with a reason and expiry.';
  const transitive = /transitive/i.test(f.title || '');
  const to = f.fixed ? `Upgrade ${f.package.split('@')[0]} to ${f.fixed}.` : `Upgrade ${f.package.split('@')[0]} to a patched version (see advisory).`;
  return transitive ? `${to} Transitive: pin the newer version directly (Directory.Packages.props).` : to;
}
const STATUS_TEXT = { PASS: 'Passed', FAIL: 'Blocking findings', 'NOT-RUN': 'Not run (tool missing)', ERROR: 'Tool error', 'NO-COVERAGE': 'Nothing to scan', 'N/A': 'Not applicable' };

export function buildHtml(rep, project) {
  const failOn = rep.failOn || 'high';
  const all = [];
  for (const t of rep.tools) for (const f of t.findings) all.push({ ...f, blocking: SEV[f.severity] >= SEV[failOn] });
  const by = (id) => all.filter((f) => priorityOf(f.severity) === id).sort((a, b) => SEV[b.severity] - SEV[a.severity] || String(a.id).localeCompare(String(b.id)));
  const counts = Object.fromEntries(LEVELS.map((l) => [l.id, by(l.id).length]));
  const verdictColor = { PASS: '#1d6f42', FAIL: '#b42318', INCOMPLETE: '#b54708' }[rep.verdict] || '#444';
  const notOk = rep.tools.filter((t) => !['PASS', 'FAIL', 'N/A'].includes(t.final));

  const points = [];
  points.push(`Overall verdict: <b style="color:${verdictColor}">${esc(rep.verdict)}</b> (gate fails on <b>${esc(failOn)}</b> severity and above).`);
  points.push(`Findings: <b>${counts.L0}</b> High (L0), <b>${counts.L1}</b> Medium (L1), <b>${counts.L2}</b> Low (L2).`);
  const blockers = all.filter((f) => f.blocking).length;
  points.push(blockers ? `<b>${blockers}</b> finding(s) block the release; start with L0.` : 'No finding reaches the blocking threshold.');
  if (notOk.length) points.push(`Coverage gap: ${notOk.map((t) => `<b>${esc(t.tool)}</b> (${esc(STATUS_TEXT[t.final] || t.final)})`).join(', ')}. The gate cannot be called clean until these run.`);
  if ((rep.skipped || []).length) points.push(`Skipped by user: ${rep.skipped.map(esc).join(', ')}.`);
  if (all.some((f) => !f.severityKnown)) points.push('Some findings had no severity from the tool; they are treated as Medium (marked with ?).');

  const kpi = LEVELS.map((l) => `<div class="kpi" style="border-color:${l.color};background:${l.bg}"><div class="n" style="color:${l.color}">${counts[l.id]}</div><div class="l"><b>${l.id} - ${l.name}</b><br>${esc(l.when)}</div></div>`).join('');

  const toolRows = rep.tools.map((t) => {
    const c = Object.fromEntries(LEVELS.map((l) => [l.id, t.findings.filter((f) => priorityOf(f.severity) === l.id).length]));
    const col = { PASS: '#1d6f42', FAIL: '#b42318' }[t.final] || '#b54708';
    return `<tr><td><b>${esc(t.tool)}</b><br><span class="mut">${esc((t.version || '').slice(0, 40))}</span></td><td style="color:${col}"><b>${esc(STATUS_TEXT[t.final] || t.final)}</b></td><td>${c.L0}</td><td>${c.L1}</td><td>${c.L2}</td><td class="mut">${esc(t.note || '')}</td></tr>`;
  }).join('');

  const caps = { L0: Infinity, L1: 200, L2: 100 };
  const sections = LEVELS.map((l) => {
    const list = by(l.id);
    const head = `<h2 style="border-left:6px solid ${l.color}"><span style="color:${l.color}">${l.id} - ${l.name} priority</span> <span class="mut">(${list.length}) &middot; ${esc(l.when)}</span></h2>`;
    if (!list.length) return `${head}<p class="mut">None.</p>`;
    const rows = list.slice(0, caps[l.id]).map((f, i) => `<tr><td>${i + 1}</td><td><b>${esc(f.severity)}${f.severityKnown ? '' : '?'}</b>${f.blocking ? '<br><span class="blk">BLOCKS</span>' : ''}</td><td>${esc(f.tool)}</td><td class="id">${esc(f.id)}</td><td>${esc(f.package)}<br><span class="mut">${esc(f.location)}</span></td><td>${esc(action(f))}</td></tr>`).join('');
    const more = list.length > caps[l.id] ? `<p class="mut">${list.length - caps[l.id]} more in report.json.</p>` : '';
    return `${head}<table class="f"><thead><tr><th>#</th><th>Severity</th><th>Tool</th><th>ID</th><th>Package / location</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table>${more}`;
  }).join('');

  const suppressed = rep.tools.flatMap((t) => (t.suppressedFindings || []).map((f) => `<li>${esc(t.tool)}: ${esc(f.id)} ${esc(f.package)} - ${esc(f.suppressedBy)} (until ${esc(f.until)})</li>`));
  const invalid = (rep.invalidSuppressions || []).map((e) => `<li>${esc(e.id || '(no id)')}: ${esc(e.why)}</li>`);

  return `<!doctype html><html><head><meta charset="utf-8"><title>Security Gate Report</title><style>
  @page { size: A4; margin: 14mm 12mm; }
  body { font: 10.5pt/1.4 "Segoe UI", Arial, sans-serif; color: #1f2430; }
  h1 { font-size: 22pt; margin: 0 0 2pt; } h2 { font-size: 13pt; margin: 18pt 0 6pt; padding-left: 8pt; page-break-after: avoid; }
  h3 { font-size: 11.5pt; margin: 14pt 0 4pt; } .mut { color: #667085; font-size: 9pt; } .meta { color: #475467; margin-bottom: 10pt; }
  .verdict { display: inline-block; padding: 3pt 12pt; border-radius: 4pt; color: #fff; font-weight: 700; font-size: 13pt; background: ${verdictColor}; }
  .kpis { display: flex; gap: 8pt; margin: 10pt 0; } .kpi { flex: 1; border: 1.5pt solid; border-radius: 6pt; padding: 8pt 10pt; display: flex; gap: 10pt; align-items: center; }
  .kpi .n { font-size: 26pt; font-weight: 700; line-height: 1; } .kpi .l { font-size: 9pt; }
  ul.pts { margin: 6pt 0 0 16pt; padding: 0; } ul.pts li { margin: 3pt 0; }
  table { width: 100%; border-collapse: collapse; margin: 4pt 0; } th { text-align: left; background: #f2f4f7; font-size: 9pt; }
  th, td { border: 0.6pt solid #d0d5dd; padding: 4pt 5pt; vertical-align: top; } tr { page-break-inside: avoid; } td.id { font-family: Consolas, monospace; font-size: 9pt; word-break: break-all; }
  .blk { color: #b42318; font-weight: 700; font-size: 8pt; } table.f td:nth-child(1) { width: 18pt; } table.f td:nth-child(4) { min-width: 78pt; } .legend td, .legend th { font-size: 9pt; }
  footer { margin-top: 16pt; color: #667085; font-size: 8.5pt; border-top: 0.6pt solid #d0d5dd; padding-top: 6pt; }
  </style></head><body>
  <h1>Security Gate Report</h1>
  <div class="meta"><b>${esc(project)}</b> &middot; generated ${esc(rep.generated)}</div>
  <span class="verdict">${esc(rep.verdict)}</span>
  <div class="kpis">${kpi}</div>
  <h3>Key points</h3><ul class="pts">${points.map((p) => `<li>${p}</li>`).join('')}</ul>
  <h2 style="border-left:6px solid #475467">Tool results</h2>
  <table><thead><tr><th>Tool</th><th>Result</th><th>L0</th><th>L1</th><th>L2</th><th>Notes</th></tr></thead><tbody>${toolRows}</tbody></table>
  ${sections}
  ${suppressed.length ? `<h2 style="border-left:6px solid #475467">Accepted risks (suppressed)</h2><ul class="pts">${suppressed.join('')}</ul>` : ''}
  ${invalid.length ? `<h2 style="border-left:6px solid #475467">Suppression entries ignored</h2><ul class="pts">${invalid.join('')}</ul>` : ''}
  <h2 style="border-left:6px solid #475467">How to read this report</h2>
  <table class="legend"><thead><tr><th>Priority</th><th>Maps to severity</th><th>Meaning</th></tr></thead><tbody>
  <tr><td><b>L0 - High</b></td><td>Critical, High</td><td>Fix now. Any secret leak is L0 (rotate the credential first).</td></tr>
  <tr><td><b>L1 - Medium</b></td><td>Medium (and unknown)</td><td>Fix in the current sprint.</td></tr>
  <tr><td><b>L2 - Low</b></td><td>Low, Negligible</td><td>Track and fix when convenient.</td></tr></tbody></table>
  <footer>Produced by Security Gate (gitleaks, NuGet Audit, semgrep, osv-scanner, grype). Scanners report known issues only; a PASS is not a penetration test. Secret values are never included in this report.</footer>
  </body></html>`;
}

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
    const r = spawnSync(browser, ['--headless', '--disable-gpu', '--no-pdf-header-footer', `--user-data-dir=${prof}`, `--print-to-pdf=${pdfPath}`, pathToFileURL(htmlPath).href], { encoding: 'utf8', timeout: 120000, windowsHide: true });
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
