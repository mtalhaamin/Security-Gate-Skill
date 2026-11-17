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
// Colours follow the PatternFly 6 status / severity palette (the design system behind Red Hat's consoles).
const LEVELS = [
  { id: 'L0', name: 'High', when: 'Fix now, blocks release', color: '#B1380B', soft: '#FBEFEA' },
  { id: 'L1', name: 'Medium', when: 'Fix in the current sprint', color: '#A36E00', soft: '#FDF6E3' },
  { id: 'L2', name: 'Low', when: 'Track, fix when convenient', color: '#4D4D4D', soft: '#F2F2F2' },
];
const LEVEL = Object.fromEntries(LEVELS.map((l) => [l.id, l]));
const SEVERITIES = [
  { id: 'critical', name: 'Critical', color: '#B1380B', text: '#B1380B' }, { id: 'high', name: 'High', color: '#CA6C0F', text: '#B25A00' },
  { id: 'medium', name: 'Medium', color: '#DCA614', text: '#8F6A0A' }, { id: 'low', name: 'Low', color: '#707070', text: '#4D4D4D' },
];
const SEV = { low: 1, medium: 2, high: 3, critical: 4 };

// ---- security grade and score
// Grade A-E uses SonarQube's published security-rating rule: the single worst open finding decides it
// (E critical, D high, C medium, B low, A none). The 0-100 score starts at 100 and subtracts points per distinct
// issue (critical 25, high 10 up to 60, medium 3 up to 30, low 1 up to 10); these weights are this project's own.
// If a check did not run, the result is incomplete and the grade can be no better than C.
export const GRADE_COLOR = { A: '#3D7317', B: '#5C8A28', C: '#A36E00', D: '#CA6C0F', E: '#B1380B' };
export function securityScore(rep) {
  const worst = new Map();
  for (const t of rep.tools || []) for (const f of t.findings || []) {
    const k = `${t.tool}|${f.id}`; if (!worst.has(k) || SEV[f.severity] > SEV[worst.get(k)]) worst.set(k, f.severity);
  }
  const ic = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const s of worst.values()) ic[s in ic ? s : 'medium']++;
  let grade = ic.critical ? 'E' : ic.high ? 'D' : ic.medium ? 'C' : ic.low ? 'B' : 'A';
  const score = Math.max(0, 100 - (25 * ic.critical + Math.min(60, 10 * ic.high) + Math.min(30, 3 * ic.medium) + Math.min(10, ic.low)));
  const applicable = (rep.tools || []).filter((t) => t.final !== 'N/A');
  const ran = applicable.filter((t) => t.final === 'PASS' || t.final === 'FAIL').length;
  const total = applicable.length + (rep.skipped || []).length;
  const complete = ran === total;
  let capped = false;
  if (!complete && (grade === 'A' || grade === 'B')) { grade = 'C'; capped = true; }
  return { grade, score, coverage: { ran, total }, complete, capped, issues: ic };
}
// ---- OWASP Top 10:2025 (official category names and mapped CWEs in references/owasp-top10-2025.json)
const OWASP = (() => { try { return JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'references', 'owasp-top10-2025.json'), 'utf8')); } catch { return null; } })();
const OWASP_BY_ID = Object.fromEntries((OWASP?.categories || []).map((c) => [c.id, c]));
const OWASP_BY_CWE = new Map((OWASP?.categories || []).flatMap((c) => c.cwes.map((n) => [n, c.id])));
// Which checks in this gate can find problems of each category, and how much of the category automation can cover.
export const OWASP_CHECKS = {
  A01: { tools: ['semgrep', 'zap'], depth: 'partial' }, A02: { tools: ['trivy', 'zap', 'semgrep'], depth: 'good' },
  A03: { tools: ['nuget', 'osv', 'grype', 'trivy'], depth: 'good' }, A04: { tools: ['semgrep', 'zap'], depth: 'partial' },
  A05: { tools: ['semgrep', 'zap'], depth: 'good' }, A06: { tools: [], depth: 'manual' },
  A07: { tools: ['gitleaks', 'semgrep', 'zap'], depth: 'partial' }, A08: { tools: ['semgrep', 'trivy'], depth: 'partial' },
  A09: { tools: [], depth: 'manual' }, A10: { tools: ['semgrep', 'zap'], depth: 'partial' },
};
// The OWASP Top 10:2025 category of a finding, or null. Vulnerable libraries are A03 (supply chain), IaC/Dockerfile
// settings A02, leaked secrets go by CWE-798 (A07); Semgrep's own OWASP tag wins (2021 tags are translated), else its CWE.
export function owaspCategory(f) {
  if (!OWASP) return null;
  const title = String(f.title || '');
  if (['nuget', 'osv', 'grype'].includes(f.tool) || (f.tool === 'trivy' && !/\[(misconfiguration|secret)\]/i.test(title))) return 'A03';
  if (f.tool === 'trivy' && /\[misconfiguration\]/i.test(title)) return 'A02';
  if (f.tool === 'gitleaks' || (f.tool === 'trivy' && /\[secret\]/i.test(title))) return OWASP_BY_CWE.get(798) || null;
  const tags = f.owasp || [];
  const t25 = tags.find((t) => t.endsWith(':2025')); if (t25 && OWASP_BY_ID[t25.slice(0, 3)]) return t25.slice(0, 3);
  const t21 = tags.find((t) => t.endsWith(':2021')); if (t21 && OWASP.from2021?.[t21.slice(0, 3)]) return OWASP.from2021[t21.slice(0, 3)];
  for (const c of f.cwe || []) if (OWASP_BY_CWE.has(c)) return OWASP_BY_CWE.get(c);
  return null;
}
const owaspLabel = (id) => (id && OWASP_BY_ID[id] ? `${id}:2025 ${OWASP_BY_ID[id].name}` : '');
const FONT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'assets', 'fonts');
// Red Hat Display / Red Hat Text (SIL Open Font License 1.1, see assets/fonts/OFL.txt), embedded so the PDF looks the
// same on every machine. Missing files simply fall back to Segoe UI / Arial.
function fontFaces() {
  return [['Red Hat Display', 700, 'red-hat-display-latin-700-normal.woff2'], ['Red Hat Display', 800, 'red-hat-display-latin-800-normal.woff2'],
    ['Red Hat Text', 400, 'red-hat-text-latin-400-normal.woff2'], ['Red Hat Text', 500, 'red-hat-text-latin-500-normal.woff2'], ['Red Hat Text', 700, 'red-hat-text-latin-700-normal.woff2']]
    .map(([fam, w, file]) => { try { return `@font-face { font-family: "${fam}"; font-weight: ${w}; font-style: normal; src: url(data:font/woff2;base64,${fs.readFileSync(path.join(FONT_DIR, file)).toString('base64')}) format("woff2"); }`; } catch { return ''; } })
    .join('\n');
}
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
const pct = (n, total) => { if (!total || !n) return '0%'; const p = Math.round((n / total) * 100); return p === 0 ? '&lt;1%' : `${p}%`; };
const titleOf = (f) => String(f.title || '').replace(/^\[[^\]]+\]\s*/, '') || f.id;

export function buildHtml(rep, project) {
  const failOn = rep.failOn || 'high';
  const all = [];
  for (const t of rep.tools) for (const f of t.findings) all.push({ ...f, blocking: SEV[f.severity] >= SEV[failOn] });
  const counts = Object.fromEntries(LEVELS.map((l) => [l.id, all.filter((f) => priorityOf(f.severity) === l.id).length]));
  const sevCounts = Object.fromEntries(SEVERITIES.map((s) => [s.id, all.filter((f) => f.severity === s.id).length]));
  const total = all.length; const blockers = all.filter((f) => f.blocking).length;
  const vcolor = { PASS: '#3D7317', FAIL: '#B1380B', INCOMPLETE: '#A36E00' }[rep.verdict] || '#4D4D4D';
  const sc = securityScore(rep);
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
  issues.forEach((g, i) => { g.no = i + 1; g.detailed = g.no <= MAX_PAGES; g.owasp = owaspCategory(g.sample); });
  const noOf = new Map(issues.map((g) => [`${g.tool}|${g.id}`, g]));
  const jump = (g, inner) => (g && g.detailed ? `<a class="lnk" href="#issue-${g.no}">${inner}</a>` : inner);

  // ---- key points
  const points = [];
  points.push(blockers ? `<b>${blockers}</b> finding(s) in <b>${issues.filter((g) => g.items.some((f) => f.blocking)).length}</b> issue(s) reach the <b>${esc(failOn)}</b> threshold and block the release. Start with <b>L0</b>.` : `No finding reaches the <b>${esc(failOn)}</b> blocking threshold.`);
  if (notOk.length) points.push(`Coverage gap: ${notOk.map((t) => `<b>${esc(TOOL_LABEL[t.tool] || t.tool)}</b> (${esc((STATUS[t.final] || [t.final])[0].toLowerCase())})`).join(', ')}. The gate cannot be called clean until these run.`);
  if ((rep.skipped || []).length) points.push(`Skipped by request: ${rep.skipped.map(esc).join(', ')}.`);
  if (partial) points.push(esc(partial));
  if (all.some((f) => !f.severityKnown)) points.push('Findings marked <b>?</b> had no severity from the tool and are treated as Medium.');
  if (all.some((f) => f.tool !== 'gitleaks' && /probable false positive/i.test(f.title || ''))) points.push(`<b>${all.filter((f) => f.tool !== 'gitleaks' && /probable false positive/i.test(f.title || '')).length}</b> dependency finding(s) are <b>probable false positives</b> (an assembly version such as 10.0.0.0 read as the package version). They are ranked <b>Low</b>; the severity the tool reported is kept in the title. NuGet Audit checks the real package versions.`);
  const guidHits = all.filter((f) => f.tool === 'gitleaks' && /guid-like/i.test(f.title || '')).length;
  if (guidHits) points.push(`<b>${guidHits}</b> secret hit(s) only contain a GUID and are ranked <b>Low</b> as probable false positives (identifiers, not passwords).`);
  points.push(`Every issue has its own numbered page (<b>1 to ${issues.length}</b>). Click a row in the <a class="lnk" href="#index">issue index</a> to jump to it.`);

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

  // ---- which checks this report covers (shown under the date)
  const lbl = (t) => esc(TOOL_LABEL[t.tool] || t.tool);
  const ranT = rep.tools.filter((t) => t.final === 'PASS' || t.final === 'FAIL');
  const naT = rep.tools.filter((t) => t.final === 'N/A');
  const missT = rep.tools.filter((t) => !['PASS', 'FAIL', 'N/A'].includes(t.final));
  const toolsLine = `<b>Checked with:</b> ${ranT.map(lbl).join(', ') || 'none'}`
    + (missT.length || (rep.skipped || []).length ? ` &nbsp;&middot;&nbsp; <span class="no">Did not run:</span> ${[...missT.map(lbl), ...(rep.skipped || []).map((s) => esc(TOOL_LABEL[s] || s))].join(', ')}` : '')
    + (naT.length ? ` &nbsp;&middot;&nbsp; Not applicable: ${naT.map(lbl).join(', ')}` : '')
    + (!rep.tools.some((t) => t.tool === 'zap') && !(rep.skipped || []).includes('zap') ? ' &nbsp;&middot;&nbsp; Not included: OWASP ZAP (running website; add <code>--dast-auto</code>)' : '');

  // ---- OWASP Top 10:2025 coverage: what each category was checked with, what was found, what needs a human
  const ranIds = new Set(ranT.map((t) => t.tool));
  const owaspRows = (OWASP?.categories || []).map((c) => {
    const chk = OWASP_CHECKS[c.id] || { tools: [], depth: 'manual' };
    const open = issues.filter((g) => g.owasp === c.id);
    const by = [...new Set([...chk.tools.filter((t) => ranIds.has(t)), ...open.map((g) => g.tool)])];
    const worst = open.reduce((w, g) => (g.sevN > w ? g.sevN : w), 0);
    const wsev = SEVERITIES.find((s) => SEV[s.id] === worst);
    let status;
    if (open.length) status = `<span class="ost" style="color:${wsev ? wsev.text : '#151515'}"><b>${open.length} issue${open.length === 1 ? '' : 's'}</b>${wsev ? ` (worst: ${wsev.name.toLowerCase()})` : ''}</span> ${open.slice(0, 4).map((g) => jump(g, `<span class="nb sm" style="background:${LEVEL[priorityOf(g.severity)].color}">${g.no}</span>`)).join(' ')}${open.length > 4 ? ' <span class="mut small">...</span>' : ''}`;
    else if (chk.depth === 'manual') status = '<span class="mut">Manual review needed: scanners cannot judge design or logging.</span>';
    else if (!by.length) status = '<span class="no">Not checked in this run</span>';
    else status = chk.depth === 'partial' ? '<span class="okk">No issues found</span> <span class="mut small">(partly automated; also review by hand)</span>' : '<span class="okk">No issues found</span>';
    return `<tr><td class="oid">${esc(c.id)}</td><td><a class="lnk" href="${esc(c.url)}">${esc(c.name)}</a></td><td class="small">${by.map((t) => esc(TOOL_LABEL[t] || t)).join(', ') || '<span class="mut">-</span>'}</td><td class="small">${status}</td></tr>`;
  }).join('');
  const unmapped = issues.filter((g) => !g.owasp).length;
  const owaspSection = OWASP ? `<h2>OWASP Top 10:2025 coverage</h2>
    <p class="small mut">Each finding is placed in its OWASP Top 10:2025 category using OWASP's official CWE list (vulnerable libraries count as A03, Software Supply Chain Failures). Scanners can only check part of the list; categories marked for review need a person.</p>
    <table class="owasp"><thead><tr><th>ID</th><th>Category</th><th>Checked with</th><th>Result</th></tr></thead><tbody>${owaspRows}</tbody></table>
    ${unmapped ? `<p class="small mut" style="margin-top:4pt">${unmapped} issue${unmapped === 1 ? ' has' : 's have'} no OWASP Top 10 category (the tool gave no CWE that OWASP maps).</p>` : ''}` : '';

  // ---- page 1: grade, score, KPIs, top 3 and a plain-language summary
  const gcol = GRADE_COLOR[sc.grade];
  const blockIssues = issues.filter((g) => g.items.some((f) => f.blocking));
  const sevWord = (n, w) => `${n} ${w}`;
  const blockMix = ['critical', 'high', 'medium', 'low'].map((s) => [s, blockIssues.filter((g) => g.severity === s).length]).filter(([, n]) => n).map(([s, n]) => sevWord(n, s)).join(', ');
  const gradeWhy = { E: 'at least one <b>critical</b> issue is open', D: 'at least one <b>high</b> issue is open', C: sc.capped ? 'not every check ran (the grade cannot be higher until they do)' : 'the worst open issue is <b>medium</b>', B: 'only <b>low</b> issues are open', A: 'no issues were found' }[sc.grade];
  const facts = [
    blockers ? `<b>${blockers} finding${blockers === 1 ? '' : 's'} in ${blockIssues.length} issue${blockIssues.length === 1 ? '' : 's'} block the release</b> (${blockMix}).` : `<b>Nothing blocks the release</b> (threshold: ${esc(failOn)} and above).`,
    `<b>${sc.coverage.ran} of ${sc.coverage.total} checks ran</b>${sc.complete ? ', so this result is complete.' : `; the result is <b>incomplete</b>.`}`,
    `Grade ${sc.grade} because ${gradeWhy}.`,
  ];
  const ring = `<div class="ring" style="background:conic-gradient(${gcol} 0 ${sc.score}%, #F2F2F2 ${sc.score}% 100%)"><div><b>${sc.score}</b><span>of 100</span></div></div>`;
  const hero = `<div class="hero"><div class="grade" style="background:${gcol}"><div class="g">${sc.grade}</div><div class="l">Security grade</div></div>
    <div class="scorebox">${ring}<div class="facts"><span class="pill" style="background:${vcolor}">${esc(rep.verdict)}</span><p>${facts.join('<br>')}</p></div></div></div>`;
  const kpis = `<div class="kpis">${SEVERITIES.map((s) => `<div class="kpi" style="border-left-color:${s.color}"><div class="n" style="color:${s.text}">${sevCounts[s.id]}</div><div class="t">${s.name}</div></div>`).join('')}</div>`;
  const dist = total ? `<div class="dist">${SEVERITIES.filter((s) => sevCounts[s.id]).map((s) => `<div style="flex:${sevCounts[s.id]};background:${s.color}"></div>`).join('')}</div>
    <div class="legend">${SEVERITIES.map((s) => `<span><i style="background:${s.color}"></i>${s.name} ${pct(sevCounts[s.id], total)}</span>`).join('')}<span class="mut">${total} finding${total === 1 ? '' : 's'} in ${issues.length} issue${issues.length === 1 ? '' : 's'}</span></div>` : '<p class="mut small" style="margin-top:8pt">No findings.</p>';
  const where = (g) => { const f = g.items[0]; return f.package ? `${f.package}${g.items.length > 1 ? ` (+${g.items.length - 1} more)` : ''}` : `${f.location}${g.items.length > 1 ? ` (+${g.items.length - 1} more)` : ''}`; };
  const top3 = issues.slice(0, 3).map((g) => {
    const lv = LEVEL[priorityOf(g.severity)];
    return `<tr><td class="num">${jump(g, `<span class="nb" style="background:${lv.color}">${g.no}</span>`)}</td><td>${jump(g, esc(titleOf(g.sample)))}<br><code>${esc(where(g))}</code></td><td>${sevTag(g.severity, g.known)}</td><td>${esc(TOOL_LABEL[g.tool] || g.tool)}</td><td class="small">${esc(action(g.sample))}</td></tr>`;
  }).join('');
  const after = (() => { // grade once every blocking issue is fixed
    const left = issues.filter((g) => !g.items.some((f) => f.blocking));
    const w = Math.max(0, ...left.map((g) => g.sevN));
    return w >= 4 ? 'E' : w === 3 ? 'D' : w === 2 ? 'C' : w === 1 ? 'B' : 'A';
  })();
  const firstFix = issues[0] ? `${esc(titleOf(issues[0].sample).replace(/[.\s]+$/, ''))} (${esc(TOOL_LABEL[issues[0].tool] || issues[0].tool)})` : '';
  const summaryText = rep.verdict === 'INCOMPLETE'
    ? `The result is <b>not complete</b>: ${notOk.map((t) => esc(TOOL_LABEL[t.tool] || t.tool)).join(', ') || esc((rep.skipped || []).join(', '))} did not run. Fix that (run <code>--preflight</code>) and scan again before relying on the grade.${blockers ? ` ${blockers} finding(s) already block the release; start with ${firstFix}.` : ''}`
    : blockers
      ? `The release is <b>blocked</b> by ${blockIssues.length} issue${blockIssues.length === 1 ? '' : 's'}. Start with ${firstFix}, then work down the list. Once every blocking issue is fixed the grade rises to <b>${after}</b>${after === 'A' ? '' : ' (lower-priority issues remain)'}.`
      : issues.length
        ? `<b>Nothing blocks the release.</b> ${issues.length} lower-priority issue${issues.length === 1 ? '' : 's'} remain${issues.length === 1 ? 's' : ''}; fixing them raises the grade to A.`
        : '<b>No known problems were found</b> by any of the checks. This is not a penetration test: it covers known issues only.';

  // ---- scan details
  const toolRows = rep.tools.map((t) => {
    const [label, kind] = STATUS[t.final] || [t.final, 'warn'];
    return `<tr><td><b>${esc(TOOL_LABEL[t.tool] || t.tool)}</b><br><span class="mut small">${esc(CATEGORY[t.tool] || '')}</span></td><td>${chip(label, kind)}</td><td class="num">${t.findings.length}</td><td class="small mut">${esc(t.version || '')}</td><td class="small mut">${esc(t.note || '')}</td></tr>`;
  }).join('');

  // ---- clickable issue index
  const indexRows = issues.map((g) => {
    const lv = LEVEL[priorityOf(g.severity)];
    return `<tr><td class="num">${jump(g, `<span class="nb" style="background:${lv.color}">${g.no}</span>`)}</td><td><b style="color:${lv.color}">${lv.id}</b></td><td>${sevTag(g.severity, g.known)}</td><td>${esc(TOOL_LABEL[g.tool] || g.tool)}</td><td class="id">${jump(g, esc(g.id))}</td><td class="small">${jump(g, esc(titleOf(g.sample).slice(0, 90)))}${g.owasp ? `<br><span class="otag">${esc(g.owasp)}:2025 ${esc(OWASP_BY_ID[g.owasp].name)}</span>` : ''}</td><td class="num">${g.items.length}</td></tr>`;
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
      <tr><th>Affected items</th><td>${g.items.length}</td><th>Fixed in</th><td>${g.fixed.size ? esc([...g.fixed].slice(0, 3).join(', ')) : '-'}</td></tr>
      <tr><th>OWASP Top 10</th><td>${g.owasp ? `<a class="lnk" href="${esc(OWASP_BY_ID[g.owasp].url)}">${esc(owaspLabel(g.owasp))}</a>` : '<span class="mut">Not mapped</span>'}</td><th>CWE</th><td>${(f.cwe || []).length ? f.cwe.slice(0, 3).map((n) => `CWE-${n}`).join(', ') : (g.owasp === 'A03' ? 'Known vulnerable component' : '-')}</td></tr></table>
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
  ${fontFaces()}
  @page { size: A4; margin: 20mm 15mm 17mm;
    @top-left { content: "Security Gate  ·  Scan report"; font: 700 8.5pt "Red Hat Display", "Segoe UI", Arial, sans-serif; color: #151515; }
    @top-right { content: "CONFIDENTIAL  |  ${pn}"; font: 8pt "Red Hat Text", "Segoe UI", Arial, sans-serif; color: #4D4D4D; }
    @bottom-left { content: "Secret values are never included in this report."; font: 7.5pt "Red Hat Text", "Segoe UI", Arial, sans-serif; color: #707070; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt "Red Hat Text", "Segoe UI", Arial, sans-serif; color: #4D4D4D; } }
  * { box-sizing: border-box; } html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { font: 9.6pt/1.45 "Red Hat Text", "Segoe UI", Arial, sans-serif; color: #151515; margin: 0; }
  a.lnk, a.lnk:visited { color: #0066CC; text-decoration: none; font-weight: 500; } a.lnk:hover { text-decoration: underline; }
  code, td.id { font: 8.2pt Consolas, "Courier New", monospace; } code { color: #4D4D4D; word-break: break-all; }
  table.top3 { table-layout: fixed; } table.top3 th:nth-child(1) { width: 30pt; } table.top3 th:nth-child(3) { width: 62pt; }
  table.top3 th:nth-child(4) { width: 66pt; } table.top3 th:nth-child(5) { width: 38%; } table.top3 td { overflow-wrap: anywhere; }
  .nb { display: inline-block; min-width: 22pt; padding: 2pt 6pt; border-radius: 11pt; color: #fff; font-weight: 700; font-size: 9pt; text-align: center; line-height: 1.15; }
  .mut { color: #4D4D4D; } .small { font-size: 8.4pt; } .num { text-align: center; width: 26pt; color: #4D4D4D; } td.nz { font-weight: 700; color: #151515; }
  h1, h2, h3, .g, .ring b, .kpi .n { font-family: "Red Hat Display", "Segoe UI", Arial, sans-serif; }
  .accent { height: 5pt; background: #EE0000; margin: 0 0 14pt; }
  .eyebrow { font-size: 7.8pt; letter-spacing: 1.4pt; text-transform: uppercase; color: #4D4D4D; font-weight: 700; }
  h1 { font-size: 23pt; font-weight: 800; margin: 2pt 0 2pt; letter-spacing: -.3pt; }
  .metaline { color: #4D4D4D; font-size: 9pt; } .metaline b { color: #151515; }
  .otag { display: inline-block; margin-top: 2pt; font-size: 7pt; color: #4D4D4D; font-weight: 700; letter-spacing: .2pt; }
  table.owasp { table-layout: fixed; } table.owasp th:nth-child(1) { width: 30pt; } table.owasp th:nth-child(2) { width: 34%; } table.owasp th:nth-child(3) { width: 24%; }
  table.owasp td.oid { font-weight: 700; } .ost { margin-right: 4pt; } .okk { color: #3D7317; font-weight: 700; } .no { color: #A36E00; font-weight: 700; }
  .nb.sm { min-width: 15pt; padding: 0.5pt 4pt; font-size: 7.4pt; border-radius: 8pt; }
  .toolsline { margin-top: 4pt; font-size: 8.4pt; color: #4D4D4D; line-height: 1.5; } .toolsline b { color: #151515; } .toolsline .no { color: #A36E00; font-weight: 700; }
  .hero { display: flex; gap: 10pt; margin: 14pt 0 10pt; align-items: stretch; }
  .grade { width: 98pt; border-radius: 7pt; color: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 8pt 0; }
  .grade .g { font-size: 46pt; font-weight: 800; line-height: 1; } .grade .l { font-size: 6.8pt; letter-spacing: 1pt; text-transform: uppercase; margin-top: 3pt; font-weight: 700; }
  .scorebox { flex: 1; border: 0.8pt solid #E0E0E0; border-radius: 7pt; padding: 10pt 14pt; display: flex; gap: 16pt; align-items: center; }
  .ring { width: 76pt; height: 76pt; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex: none; }
  .ring div { width: 58pt; height: 58pt; border-radius: 50%; background: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .ring b { font-size: 19pt; font-weight: 800; line-height: 1; } .ring span { font-size: 6.6pt; color: #4D4D4D; }
  .facts { flex: 1; } .facts p { margin-top: 5pt; font-size: 8.8pt; line-height: 1.5; color: #4D4D4D; } .facts p b { color: #151515; }
  .pill { display: inline-block; font-weight: 700; font-size: 9.5pt; letter-spacing: 1pt; color: #fff; padding: 2pt 11pt; border-radius: 99pt; }
  .kpis { display: flex; gap: 7pt; } .kpi { flex: 1; border: 0.8pt solid #E0E0E0; border-left: 4pt solid; border-radius: 5pt; padding: 6pt 9pt; }
  .kpi .n { font-size: 17pt; font-weight: 800; line-height: 1.1; } .kpi .t { font-size: 7pt; text-transform: uppercase; letter-spacing: .8pt; color: #4D4D4D; font-weight: 700; }
  .dist { display: flex; height: 8pt; border-radius: 4pt; overflow: hidden; margin: 10pt 0 3pt; }
  .legend { font-size: 7.8pt; color: #4D4D4D; display: flex; gap: 12pt; } .legend i { display: inline-block; width: 7pt; height: 7pt; border-radius: 1.5pt; margin-right: 4pt; vertical-align: -0.5pt; }
  .legend span.mut { margin-left: auto; }
  .summarybox { background: #F2F2F2; border-left: 3pt solid #EE0000; padding: 8pt 11pt; margin-top: 12pt; font-size: 9pt; line-height: 1.5; }
  .conf { margin-top: 8pt; font-size: 7.6pt; color: #707070; }
  h2 { font-size: 12pt; font-weight: 700; margin: 16pt 0 5pt; padding-bottom: 3pt; border-bottom: 1.2pt solid #151515; page-break-after: avoid; }
  h3 { font-size: 13pt; font-weight: 700; margin: 2pt 0 0; line-height: 1.25; } h4 { font-size: 8pt; text-transform: uppercase; letter-spacing: .7pt; color: #4D4D4D; margin: 11pt 0 3pt; }
  p { margin: 0 0 4pt; }
  ul.pts { margin: 4pt 0 0 14pt; padding: 0; } ul.pts li { margin: 3pt 0; } ul.plain { margin: 4pt 0 0 14pt; padding: 0; font-size: 8.8pt; } ul.plain li { margin: 2pt 0; }
  table { width: 100%; border-collapse: collapse; margin-top: 3pt; }
  th { text-align: left; font-size: 7.2pt; text-transform: uppercase; letter-spacing: .6pt; color: #4D4D4D; font-weight: 700; border-bottom: 1pt solid #151515; }
  th, td { padding: 4.5pt 6pt; vertical-align: top; } td { border-bottom: 0.6pt solid #E0E0E0; } tr { page-break-inside: avoid; }
  td.id { word-break: break-all; min-width: 70pt; color: #0066CC; }
  /* fixed layout: a long rule id wraps inside its column instead of pushing the table past the page edge */
  table.idx { table-layout: fixed; } table.idx th, table.idx td { padding: 4pt 5pt; }
  table.idx th:nth-child(1) { width: 36pt; text-align: center; } table.idx td.num:first-child { text-align: center; }
  table.idx th:nth-child(2) { width: 50pt; } table.idx th:nth-child(3) { width: 58pt; } table.idx th:nth-child(4) { width: 72pt; }
  table.idx th:nth-child(5) { width: 26%; } table.idx th:nth-child(7) { width: 34pt; text-align: center; } table.idx td:last-child { text-align: center; }
  table.idx td.id { word-break: break-all; font-size: 7.6pt; }
  table.idx a.lnk { font-weight: 400; } table.idx td.num a.lnk { font-weight: 700; }
  .chip { display: inline-block; padding: 1pt 7pt; border-radius: 99pt; font-size: 7.6pt; font-weight: 700; white-space: nowrap; }
  .chip.ok { background: #F3FAF2; color: #3D7317; border: 0.6pt solid #3D7317; } .chip.bad { background: #FBEFEA; color: #B1380B; border: 0.6pt solid #B1380B; }
  .chip.warn { background: #FDF6E3; color: #8F6A0A; border: 0.6pt solid #DCA614; } .chip.mut { background: #F2F2F2; color: #4D4D4D; border: 0.6pt solid #C7C7C7; }
  .sev { display: inline-block; padding: 1pt 6pt; border-radius: 2.5pt; font-size: 7.4pt; font-weight: 700; text-transform: uppercase; color: #fff; background: #707070; }
  .s-critical { background: #B1380B; } .s-high { background: #CA6C0F; } .s-medium { background: #DCA614; color: #151515; } .s-low { background: #707070; }
  section.issue { break-before: page; page-break-before: always; }
  .ihead { display: flex; gap: 12pt; align-items: center; background: var(--s); border-left: 5pt solid var(--c); border-radius: 4pt; padding: 11pt 13pt; margin-bottom: 11pt; }
  .ino { min-width: 46pt; height: 46pt; line-height: 46pt; text-align: center; border-radius: 50%; background: var(--c); color: #fff; font: 800 21pt "Red Hat Display", "Segoe UI", sans-serif; }
  .ilab { font-size: 7.8pt; color: #4D4D4D; text-transform: uppercase; letter-spacing: .6pt; font-weight: 700; }
  table.kv { margin: 0 0 2pt; } table.kv th { width: 78pt; background: #F2F2F2; color: #151515; border-bottom: 0.6pt solid #E0E0E0; text-transform: none; font-size: 8.2pt; letter-spacing: 0; font-weight: 700; }
  .nav { margin-top: 14pt; padding-top: 7pt; border-top: 0.6pt solid #E0E0E0; display: flex; justify-content: space-between; font-size: 9pt; }
  .legendt td { font-size: 8.8pt; }
  .foot { margin-top: 16pt; padding-top: 7pt; border-top: 0.6pt solid #E0E0E0; color: #4D4D4D; font-size: 8pt; }
  </style></head><body>
  <div class="accent"></div>
  <div class="eyebrow">Security Gate &nbsp;&middot;&nbsp; Executive summary</div>
  <h1>Security scan report</h1>
  <div class="metaline"><b>${esc(project)}</b> &nbsp;&middot;&nbsp; ${esc(date)} &nbsp;&middot;&nbsp; the gate fails on ${esc(failOn)} and above${partial ? ` &nbsp;&middot;&nbsp; ${esc(partial)}` : ''}</div>
  <div class="toolsline">${toolsLine}</div>
  ${hero}
  ${kpis}
  ${dist}
  ${top3 ? `<h2>Fix these first</h2><table class="top3"><thead><tr><th>#</th><th>Issue</th><th>Severity</th><th>Tool</th><th>What to do</th></tr></thead><tbody>${top3}</tbody></table>` : ''}
  <div class="summarybox"><b>Summary.</b> ${summaryText}</div>
  <div class="conf">CONFIDENTIAL. This report lists internal file paths and package names. Scanners report known issues only; a pass is not a penetration test. Secret values are never included.</div>

  <h2 style="break-before: page; page-break-before: always;">Key points</h2>
  <ul class="pts">${points.map((p) => `<li>${p}</li>`).join('')}</ul>

  ${owaspSection}

  <h2>Checks run</h2>
  <table><thead><tr><th>Area</th><th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th><th class="num">Low</th><th class="num">Total</th><th>Status</th></tr></thead><tbody>${catRows}</tbody></table>

  ${fixFirst.length ? `<h2>Action plan</h2><table><thead><tr><th>#</th><th>What to do</th><th>Tool</th><th>Advisory / rule (click)</th><th>Items</th><th>Issue</th></tr></thead><tbody>${fixRows}</tbody></table>` : ''}

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
  <table class="legendt"><thead><tr><th>Priority</th><th>Severity covered</th><th>Meaning</th></tr></thead><tbody>
  <tr><td><b style="color:#B1380B">L0 &middot; High</b></td><td>Critical, High</td><td>Fix now. Any secret leak is L0: rotate the credential first.</td></tr>
  <tr><td><b style="color:#A36E00">L1 &middot; Medium</b></td><td>Medium, unknown severity</td><td>Fix in the current sprint.</td></tr>
  <tr><td><b style="color:#4D4D4D">L2 &middot; Low</b></td><td>Low, Negligible</td><td>Track and fix when convenient.</td></tr></tbody></table>
  <h2>How the grade and score are worked out</h2>
  <table class="legendt"><thead><tr><th>Grade</th><th>When</th></tr></thead><tbody>
  <tr><td><b style="color:${GRADE_COLOR.A}">A</b></td><td>No open findings.</td></tr>
  <tr><td><b style="color:${GRADE_COLOR.B}">B</b></td><td>Only low findings.</td></tr>
  <tr><td><b style="color:${GRADE_COLOR.C}">C</b></td><td>At least one medium finding, or a check did not run (the grade is capped at C until every check runs).</td></tr>
  <tr><td><b style="color:${GRADE_COLOR.D}">D</b></td><td>At least one high finding.</td></tr>
  <tr><td><b style="color:${GRADE_COLOR.E}">E</b></td><td>At least one critical finding.</td></tr></tbody></table>
  <p class="small mut" style="margin-top:5pt">The grade follows SonarQube's security-rating rule: the single worst open finding decides it. The score starts at 100 and subtracts points for each distinct issue: critical 25, high 10 (at most 60), medium 3 (at most 30), low 1 (at most 10). The score shows progress inside a grade; the grade always wins. Suppressed findings do not count.</p>
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
