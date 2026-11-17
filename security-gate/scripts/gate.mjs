#!/usr/bin/env node
// security-gate runner: gitleaks + NuGet Audit + semgrep + osv-scanner + grype -> one verdict.
// Node >= 20, no npm dependencies. The script NEVER installs anything. It only runs tools that
// are already on PATH and says exactly what is missing (see --preflight).
//
// Exit codes: 0 = PASS, 1 = FAIL (blocking findings), 2 = INCOMPLETE / usage error.
// "PASS" is only printed when every selected tool really ran and nothing blocking was found.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildPdf, priorityOf } from './report-pdf.mjs';

// Portable tools folder: <Security-Gate-Skill>/tools (override with SECURITY_GATE_TOOLS). Anything installed there
// (bin/ for gitleaks, osv-scanner, grype; semgrep-venv/ for semgrep) is found before the system PATH, so the
// gate works without installing tools globally. If the folder does not exist, the normal PATH is used.
// Lookup order: env SECURITY_GATE_TOOLS, then <skill>/tools.path (written by install-skill.mjs when the skill is copied
// into a project/agent folder), then the repository layout <repo>/security-gate + <repo>/tools.
const SKILL_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
function resolveToolsDir() {
  if (process.env.SECURITY_GATE_TOOLS) return process.env.SECURITY_GATE_TOOLS;
  try { const p = fs.readFileSync(path.join(SKILL_DIR, 'tools.path'), 'utf8').trim(); if (p) return p; } catch { /* no pointer file */ }
  return path.resolve(SKILL_DIR, '..', 'tools');
}
const TOOLS_DIR = resolveToolsDir();
const LOCAL_DIRS = [path.join(TOOLS_DIR, 'bin'), path.join(TOOLS_DIR, 'semgrep-venv', 'Scripts'), path.join(TOOLS_DIR, 'semgrep-venv', 'bin')].filter((d) => fs.existsSync(d));
function childEnv() {
  const key = Object.keys(process.env).find((k) => k.toLowerCase() === 'path') || 'PATH';
  const env = { ...process.env, [key]: [...LOCAL_DIRS, process.env[key] || ''].join(path.delimiter) };
  if (fs.existsSync(TOOLS_DIR)) env.GRYPE_DB_CACHE_DIR = env.GRYPE_DB_CACHE_DIR || path.join(TOOLS_DIR, 'grype-db'); // keep grype's DB inside the folder
  return env;
}

export const TOOLS = ['gitleaks', 'nuget', 'semgrep', 'osv', 'grype'];
export const SEV = { low: 1, medium: 2, high: 3, critical: 4 };

const INSTALL = {
  gitleaks: 'winget install Gitleaks.Gitleaks   (or: choco install gitleaks)',
  semgrep: 'pip install semgrep   (or: pipx install semgrep)',
  osv: 'winget install Google.OSVScanner',
  grype: 'winget install Anchore.Grype   (or: choco install grype)',
  nuget: 'Install the .NET SDK 8 or newer (https://dotnet.microsoft.com/download)',
};
const BIN = {
  gitleaks: ['gitleaks', ['version']],
  semgrep: ['semgrep', ['--version']],
  osv: ['osv-scanner', ['--version']],
  grype: ['grype', ['version']],
  nuget: ['dotnet', ['--version']],
};
// Secret-bearing files that no scanner other than gitleaks should read or echo.
const SECRET_EXCLUDES = [
  'appsettings.Development.json', 'appsettings.*.local.json', 'appsettings.local.json', 'secrets.json',
  '.env', '.env.*', '*.pfx', '*.p12', '*.key', '*.snk', 'Umbraco-Login*', '.mcp.local.json',
];
const NOISE_EXCLUDES = ['node_modules', 'bin', 'obj', '.git', '.work', '.claude'];

// ------------------------------------------------------------------ small helpers
export function normSeverity(s) {
  const v = String(s ?? '').toLowerCase();
  if (v === 'critical') return 'critical';
  if (v === 'high' || v === 'error') return 'high';
  if (v === 'moderate' || v === 'medium' || v === 'warning') return 'medium';
  if (v === 'low' || v === 'negligible' || v === 'info') return 'low';
  return null; // unknown
}
export function cvssToSeverity(score) {
  const n = Number(score);
  if (score === '' || score == null || !Number.isFinite(n)) return null;
  return n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : 'low';
}
// Tools sometimes print a banner/warnings before the JSON; find the JSON and parse it.
export function extractJson(text) {
  if (!text) return null;
  const starts = [text.indexOf('{'), text.indexOf('[')].filter((i) => i >= 0);
  if (!starts.length) return null;
  const s = Math.min(...starts);
  for (const end of [text.length, text.lastIndexOf('}') + 1, text.lastIndexOf(']') + 1]) {
    try { return JSON.parse(text.slice(s, end)); } catch { /* try next */ }
  }
  return null;
}
function run(cmd, args, o = {}) {
  const r = spawnSync(cmd, args, {
    cwd: o.cwd, encoding: 'utf8', maxBuffer: 1 << 30, windowsHide: true,
    timeout: o.timeout ?? 20 * 60 * 1000,
    env: { ...childEnv(), PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8', DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1', ...o.env },
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', missing: r.error?.code === 'ENOENT', timedOut: r.error?.code === 'ETIMEDOUT', error: r.error };
}
const tail = (t, n = 6) => String(t || '').trim().split(/\r?\n/).slice(-n).join(' | ').slice(0, 600);
function detect(tool) {
  const [cmd, args] = BIN[tool];
  const r = run(cmd, args, { timeout: 30000 });
  if (r.missing || r.status !== 0) return { found: false, version: '' };
  return { found: true, version: (r.stdout || r.stderr).trim().split(/\r?\n/)[0] };
}
function walk(dir, depth, visit) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name.startsWith('.') || ['node_modules', 'bin', 'obj'].includes(e.name)) continue;
      if (depth > 0) walk(full, depth - 1, visit);
    } else visit(full);
  }
}
const dedupe = (arr) => { const m = new Map(); for (const f of arr) if (!m.has(f.key)) m.set(f.key, f); return [...m.values()]; };
const mk = (tool, p) => { const f = { tool, severity: 'high', severityKnown: true, package: '', fixed: '', location: '', title: '', ...p }; f.priority = priorityOf(f.severity); return f; }; // L0 high, L1 medium, L2 low

// ------------------------------------------------------------------ parsers (pure, unit-tested)
export function parseGitleaks(text, label = '') {
  const arr = extractJson(text);
  if (!Array.isArray(arr)) return [];
  // Secret/Match are never copied: only rule, file, line, commit.
  return arr.map((f) => mk('gitleaks', {
    id: f.RuleID, severity: 'critical', title: f.Description || f.RuleID,
    location: `${f.File}:${f.StartLine}` + (f.Commit ? ` @${String(f.Commit).slice(0, 8)}` : ''),
    key: f.Fingerprint || `${f.RuleID}|${f.File}|${f.StartLine}|${f.Commit || ''}`, source: label,
  }));
}
export function parseDotnetList(text) {
  const obj = extractJson(text);
  if (!obj || typeof obj !== 'object') return { findings: [], problems: [{ level: 'error', text: 'dotnet list package returned no JSON' }] };
  const out = [];
  for (const proj of obj.projects || []) {
    for (const fw of proj.frameworks || []) {
      for (const kind of ['topLevelPackages', 'transitivePackages']) {
        for (const p of fw[kind] || []) {
          for (const v of p.vulnerabilities || []) {
            const url = String(v.advisoryurl || '');
            const id = url.split('/').filter(Boolean).pop() || 'NuGet-advisory';
            const sev = normSeverity(v.severity);
            out.push(mk('nuget', {
              id, severity: sev || 'medium', severityKnown: !!sev, package: `${p.id}@${p.resolvedVersion}`,
              title: `${kind === 'transitivePackages' ? 'transitive' : 'direct'} dependency - ${url}`,
              location: `${path.basename(proj.path || '')} (${fw.framework})`,
              key: `${p.id}@${p.resolvedVersion}|${id}`,
            }));
          }
        }
      }
    }
  }
  return { findings: dedupe(out), problems: obj.problems || [] };
}
export function parseSemgrep(text) {
  const obj = extractJson(text);
  if (!obj || !Array.isArray(obj.results)) return null;
  return dedupe(obj.results.map((r) => {
    const sev = normSeverity(r.extra?.severity);
    return mk('semgrep', {
      id: r.check_id, severity: sev || 'medium', severityKnown: !!sev,
      title: String(r.extra?.message || '').replace(/\s+/g, ' ').slice(0, 200), // never r.extra.lines (may hold secrets)
      location: `${r.path}:${r.start?.line ?? '?'}`, key: `${r.check_id}|${r.path}|${r.start?.line}`,
    });
  }));
}
export function parseOsv(text, label = '', strip = '') {
  const obj = extractJson(text);
  if (!obj || !Array.isArray(obj.results)) return null;
  const out = [];
  for (const res of obj.results) {
    for (const pkg of res.packages || []) {
      const vulns = pkg.vulnerabilities || [];
      const byId = new Map(vulns.map((v) => [v.id, v]));
      const groups = (pkg.groups && pkg.groups.length) ? pkg.groups : vulns.map((v) => ({ ids: [v.id] }));
      for (const g of groups) {
        const ids = g.ids || [];
        const v = byId.get(ids[0]) || {};
        const sev = cvssToSeverity(g.max_severity) || normSeverity(v.database_specific?.severity)
          || cvssToSeverity((v.severity || []).map((s) => s.score).find((s) => !String(s).startsWith('CVSS:')));
        const id = ids.find((i) => /^CVE-/.test(i)) || ids[0] || v.id || 'OSV';
        const name = `${pkg.package?.name}@${pkg.package?.version}`;
        out.push(mk('osv', {
          id, severity: sev || 'medium', severityKnown: !!sev, package: name, title: (pkg.package?.ecosystem === 'NuGet' && /^\d+\.\d+\.\d+\.0$/.test(String(pkg.package?.version)) ? '[assembly-version, probable false positive] ' : '') + (v.summary || ''),
          location: `${label}: ${(() => { const sp = String(res.source?.path || ''); return strip && sp.toLowerCase().startsWith(strip.toLowerCase()) ? sp.slice(strip.length) : path.basename(sp); })()}`, key: `${name}|${id}|${label}|${res.source?.path}`,
        }));
      }
    }
  }
  return out;
}
export function parseGrype(text, label = '', stripPrefix = '') {
  const obj = extractJson(text);
  if (!obj || !Array.isArray(obj.matches)) return null;
  return obj.matches.map((m) => {
    const v = m.vulnerability || {}; const a = m.artifact || {};
    const sev = normSeverity(v.severity);
    const loc = String(a.locations?.[0]?.path || '');
    const name = `${a.name}@${a.version}`;
    return mk('grype', {
      id: v.id, severity: sev || 'medium', severityKnown: !!sev, package: name,
      fixed: (v.fix?.versions || []).join(','), title: `${a.type || ''} ${v.severity || ''}`.trim(),
      location: `${label}: ${stripPrefix && loc.startsWith(stripPrefix) ? loc.slice(stripPrefix.length) : loc}`,
      key: `${name}|${v.id}|${label}`,
    });
  });
}

// ------------------------------------------------------------------ suppressions + verdict (pure)
export function applyIgnores(findings, entries, now = new Date()) {
  const invalid = []; const valid = [];
  for (const e of entries || []) {
    const exp = new Date(e.expires);
    if (!e.id || !e.reason || String(e.reason).trim().length < 5 || Number.isNaN(exp.getTime())) { invalid.push({ ...e, why: 'needs id, reason (5+ chars) and expires (YYYY-MM-DD)' }); continue; }
    if (exp < now) { invalid.push({ ...e, why: 'expired - finding counts again' }); continue; }
    valid.push(e);
  }
  const active = []; const suppressed = [];
  for (const f of findings) {
    const hit = valid.find((e) => (!e.tool || e.tool === '*' || e.tool === f.tool) && e.id === f.id
      && (!e.package || f.package.includes(e.package)) && (!e.path || f.location.includes(e.path)));
    (hit ? suppressed : active).push(hit ? { ...f, suppressedBy: hit.reason, until: hit.expires } : f);
  }
  return { active, suppressed, invalid };
}
export function evaluate(results, failOn, skipped = []) {
  const th = SEV[failOn];
  for (const r of results) {
    r.blocking = r.findings.filter((f) => SEV[f.severity] >= th);
    r.belowThreshold = r.findings.length - r.blocking.length;
    r.final = r.status === 'OK' ? (r.blocking.length ? 'FAIL' : 'PASS') : r.status;
  }
  const failed = results.some((r) => r.final === 'FAIL');
  const incomplete = results.some((r) => !['PASS', 'FAIL', 'N/A'].includes(r.final)) || skipped.length > 0;
  const verdict = failed ? 'FAIL' : incomplete ? 'INCOMPLETE' : 'PASS';
  return { verdict, exitCode: { PASS: 0, FAIL: 1, INCOMPLETE: 2 }[verdict] };
}

// ------------------------------------------------------------------ .NET discovery
function findDotnetTargets(root) {
  const sols = []; const projs = [];
  walk(root, 4, (f) => {
    if (/\.(sln|slnx)$/i.test(f)) sols.push(f);
    if (/\.csproj$/i.test(f)) projs.push(f);
  });
  return { targets: sols.length ? sols : projs, projects: projs };
}
function findPublishProjects(projects) {
  return projects.filter((p) => {
    let t = ''; try { t = fs.readFileSync(p, 'utf8'); } catch { return false; }
    if (/<IsTestProject>\s*true/i.test(t) || /\.tests?\.csproj$/i.test(p)) return false;
    return /Sdk="Microsoft\.NET\.Sdk\.Web"/i.test(t) || /<OutputType>\s*(Exe|WinExe)/i.test(t);
  });
}

// ------------------------------------------------------------------ tool runners
function gitleaksConfig(ctx) {
  for (const f of ['.gitleaks.toml', 'gitleaks.toml']) {
    const p = path.join(ctx.root, f);
    if (fs.existsSync(p)) return { file: p, note: `using project config ${f}` };
  }
  // gitleaks does not read .gitignore: allow-list ignored paths so gitignored secret files are not reported as repo leaks.
  const ig = run('git', ['ls-files', '--others', '--ignored', '--exclude-standard', '--directory'], { cwd: ctx.root });
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const sep = '[\\\\/]'; // regex class: backslash or slash
  const paths = (ig.status === 0 ? ig.stdout.split(/\r?\n/).filter(Boolean) : [])
    .map((p) => `(^|${sep})${esc(p.replace(/\/$/, '')).replace(/\//g, sep)}(${sep}|$)`);
  paths.push(`(^|${sep})(node_modules|bin|obj|\\.git)${sep}`);
  const file = path.join(ctx.out, 'gitleaks.config.toml');
  fs.writeFileSync(file, `[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "gitignored and generated paths"\npaths = [\n${paths.map((p) => `  '''${p}'''`).join(',\n')}\n]\n`);
  return { file, note: `${paths.length} ignored paths allow-listed` };
}
function runGitleaks(ctx) {
  const cfg = gitleaksConfig(ctx);
  const base = ['--config', cfg.file, '--redact', '--no-banner', '--exit-code', '2', '-f', 'json'];
  const findings = []; const notes = [cfg.note];
  const scans = [['dir', path.join(ctx.out, 'gitleaks-dir.json'), 'working tree']];
  const hasCommits = run('git', ['rev-parse', '--verify', 'HEAD'], { cwd: ctx.root }).status === 0;
  if (!ctx.opts.noHistory) {
    if (hasCommits) scans.push(['git', path.join(ctx.out, 'gitleaks-git.json'), 'git history']);
    else notes.push('git history: repository has no commits yet (nothing to scan)');
  }
  for (const [mode, report, label] of scans) {
    try { fs.rmSync(report, { force: true }); } catch { /* ignore */ }
    const r = run('gitleaks', [mode, ...base, '-r', report, '.'], { cwd: ctx.root, timeout: 15 * 60 * 1000 });
    if (r.status !== 0 && r.status !== 2) return { status: 'ERROR', note: `gitleaks ${mode} failed (exit ${r.status}): ${tail(r.stderr || r.stdout)}`, findings: [] };
    let text = '[]'; try { text = fs.readFileSync(report, 'utf8'); } catch { if (r.status === 2) return { status: 'ERROR', note: `gitleaks ${mode} reported leaks but wrote no report`, findings: [] }; }
    findings.push(...parseGitleaks(text, label));
    notes.push(`${label}: scanned`);
  }
  return { status: 'OK', findings: dedupe(findings), note: notes.join('; ') };
}
function runNuget(ctx) {
  const { targets } = ctx.dotnet;
  if (!targets.length) return { status: 'N/A', findings: [], note: 'no .sln/.slnx/.csproj found - not a .NET repository' };
  const major = parseInt(String(ctx.versions.nuget).split('.')[0], 10);
  if (!(major >= 8)) return { status: 'ERROR', findings: [], note: `needs .NET SDK 8+ for "dotnet list package --format json" (found ${ctx.versions.nuget})` };
  const findings = []; const notes = [];
  for (const t of targets) {
    const rel = path.relative(ctx.root, t);
    const rs = run('dotnet', ['restore', t, '--nologo', '-v', 'q'], { cwd: ctx.root, timeout: 15 * 60 * 1000 });
    if (rs.status !== 0) return { status: 'ERROR', findings: [], note: `dotnet restore failed for ${rel}: ${tail(rs.stdout + ' ' + rs.stderr)}` };
    const ls = run('dotnet', ['list', t, 'package', '--vulnerable', '--include-transitive', '--format', 'json'], { cwd: ctx.root, timeout: 15 * 60 * 1000 });
    fs.writeFileSync(path.join(ctx.out, `nuget-${path.basename(t)}.json`), ls.stdout);
    const { findings: f, problems } = parseDotnetList(ls.stdout);
    const bad = problems.find((p) => String(p.level).toLowerCase() === 'error' || /NU1900/.test(p.text || ''));
    if (ls.status !== 0 || bad) return { status: 'ERROR', findings: [], note: `NuGet audit data unavailable for ${rel}: ${bad ? bad.text : tail(ls.stderr || ls.stdout)}` };
    findings.push(...f); notes.push(rel);
  }
  return { status: 'OK', findings: dedupe(findings), note: `audited (direct + transitive): ${notes.join(', ')}` };
}
function runSemgrep(ctx) {
  const report = path.join(ctx.out, 'semgrep.json');
  try { fs.rmSync(report, { force: true }); } catch { /* ignore */ }
  const configs = ctx.opts.semgrepConfigs.length ? ctx.opts.semgrepConfigs : ['p/security-audit', 'p/owasp-top-ten', 'p/csharp', 'p/secrets'];
  const args = ['scan', '--metrics=off', '--json', '--json-output', report, '--quiet', '--disable-version-check'];
  for (const c of configs) args.push('--config', c);
  for (const e of [...NOISE_EXCLUDES, ...SECRET_EXCLUDES, ...ctx.opts.excludes]) args.push('--exclude', e);
  args.push('.');
  const r = run('semgrep', args, { cwd: ctx.root, timeout: 30 * 60 * 1000 });
  let text = ''; try { text = fs.readFileSync(report, 'utf8'); } catch { /* none */ }
  const findings = r.status !== null && r.status < 2 ? parseSemgrep(text) : null;
  if (!findings) return { status: 'ERROR', findings: [], note: `semgrep failed (exit ${r.status}): ${tail(r.stderr || r.stdout)}` };
  const errs = (extractJson(text)?.errors || []).length;
  return { status: 'OK', findings, note: `rulesets: ${configs.join(', ')}${errs ? `; ${errs} files/rules had scan errors (see semgrep.json)` : ''}` };
}
// osv-scanner is pointed at each top-level project folder (not the repo root) so dot-folders such as .claude, .git
// and .work (tooling, not product code) are never scanned; the same folders semgrep and grype exclude.
const OSV_ROOT_FILES = /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|packages\.lock\.json|requirements\.txt|poetry\.lock|go\.mod|Cargo\.lock|composer\.lock|Gemfile\.lock|pom\.xml)$/i;
function osvRepoTargets(root) {
  const out = []; let entries = [];
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) { if (!e.name.startsWith('.') && !['node_modules', 'bin', 'obj'].includes(e.name)) out.push({ label: `repo/${e.name}`, args: ['-r', full], strip: root + path.sep }); }
    else if (OSV_ROOT_FILES.test(e.name)) out.push({ label: `repo/${e.name}`, args: ['-L', full], strip: root + path.sep });
  }
  return out;
}
function runOsv(ctx) {
  const targets = [...osvRepoTargets(ctx.root), ...ctx.pub.map((p) => ({ label: `published:${p.name}`, args: ['-r', p.dir], strip: p.dir + path.sep }))];
  const findings = []; const scanned = []; const empty = [];
  for (const t of targets) {
    const r = run('osv-scanner', ['scan', 'source', ...t.args, '--format', 'json'], { cwd: ctx.root, timeout: 15 * 60 * 1000 });
    if (r.status === 128) { empty.push(t.label); continue; } // "no packages found"
    if (r.status !== 0 && r.status !== 1) return { status: 'ERROR', findings: [], note: `osv-scanner failed on ${t.label} (exit ${r.status}): ${tail(r.stderr || r.stdout)}` };
    fs.writeFileSync(path.join(ctx.out, `osv-${t.label.replace(/[^\w.-]/g, '_')}.json`), r.stdout);
    const f = parseOsv(r.stdout, t.label, t.strip);
    if (!f) return { status: 'ERROR', findings: [], note: `osv-scanner output for ${t.label} was not valid JSON` };
    findings.push(...f); scanned.push(t.label);
  }
  if (!scanned.length) return { status: 'NO-COVERAGE', findings: [], note: `no lockfiles/manifests found in: ${empty.join(', ')}${ctx.dotnet.targets.length && !ctx.pub.length ? ' (.NET deps need a publish output; see references/tools.md)' : ''}` };
  return { status: 'OK', findings: dedupe(findings), note: `scanned: ${scanned.join(', ')}${empty.length ? `; no packages in ${empty.length} other target(s)` : ''}` };
}
function runGrype(ctx) {
  const targets = [{ label: 'repo', dir: ctx.root, excl: true }, ...ctx.pub.map((p) => ({ label: `published:${p.name}`, dir: p.dir, prefix: p.dir }))];
  const findings = [];
  for (const t of targets) {
    const args = [`dir:${t.dir}`, '-o', 'json', '-q'];
    if (t.excl) for (const g of ['node_modules', 'bin', 'obj', '.git', '.work', '.claude']) args.push('--exclude', `./**/${g}/**`);
    const r = run('grype', args, { cwd: ctx.root, timeout: 40 * 60 * 1000 });
    if (r.status !== 0) return { status: 'ERROR', findings: [], note: `grype failed on ${t.label} (exit ${r.status}): ${tail(r.stderr || r.stdout)}` };
    fs.writeFileSync(path.join(ctx.out, `grype-${t.label.replace(/[^\w.-]/g, '_')}.json`), r.stdout);
    const f = parseGrype(r.stdout, t.label, t.prefix ? t.prefix + path.sep : '');
    if (!f) return { status: 'ERROR', findings: [], note: `grype output for ${t.label} was not valid JSON` };
    findings.push(...f);
  }
  return { status: 'OK', findings: dedupe(findings), note: `scanned: ${targets.map((t) => t.label).join(', ')}` };
}
const RUNNERS = { gitleaks: runGitleaks, nuget: runNuget, semgrep: runSemgrep, osv: runOsv, grype: runGrype };

function publishDotnet(ctx) {
  const out = []; const notes = [];
  const projs = findPublishProjects(ctx.dotnet.projects);
  if (!projs.length) return { pub: out, notes: ['no publishable .NET project found'] };
  for (const p of projs) {
    const name = path.basename(p, '.csproj');
    const dir = path.join(ctx.tmp, 'publish', name);
    const r = run('dotnet', ['publish', p, '-c', 'Release', '-o', dir, '--nologo', '-v', 'q'], { cwd: ctx.root, timeout: 20 * 60 * 1000 });
    if (r.status === 0) out.push({ name, dir }); else notes.push(`publish failed for ${name}: ${tail(r.stdout + ' ' + r.stderr)}`);
  }
  return { pub: out, notes };
}

// ------------------------------------------------------------------ reports
function writeReports(ctx, results, ev, skipped, ignores, extraNotes) {
  const when = new Date().toISOString();
  const json = { generated: when, failOn: ctx.opts.failOn, verdict: ev.verdict, skipped, notes: extraNotes, invalidSuppressions: ignores.invalid,
    tools: results.map((r) => ({ tool: r.tool, final: r.final, version: r.version, seconds: r.seconds, note: r.note, blocking: r.blocking.length, belowThreshold: r.belowThreshold, suppressed: r.suppressed.length, findings: r.findings, suppressedFindings: r.suppressed })) };
  fs.writeFileSync(path.join(ctx.out, 'report.json'), JSON.stringify(json, null, 2));
  const L = [`# Security gate report`, '', `- Generated: ${when}`, `- Fail threshold: ${ctx.opts.failOn} and above`, `- **Verdict: ${ev.verdict}**`, ''];
  L.push('| Tool | Result | Blocking | Below threshold | Suppressed | Notes |', '|---|---|---|---|---|---|');
  for (const r of results) L.push(`| ${r.tool} | ${r.final} | ${r.blocking.length} | ${r.belowThreshold} | ${r.suppressed.length} | ${String(r.note || '').replace(/\|/g, '/')} |`);
  for (const s of skipped) L.push(`| ${s} | SKIPPED | - | - | - | skipped by user, gate is incomplete |`);
  for (const n of extraNotes) L.push('', `> ${n}`);
  for (const r of results) {
    if (!r.findings.length) continue;
    L.push('', `## ${r.tool} findings (${r.findings.length})`, '', '| Severity | ID | Package | Location | Detail |', '|---|---|---|---|---|');
    const sorted = [...r.findings].sort((a, b) => SEV[b.severity] - SEV[a.severity]);
    for (const f of sorted.slice(0, 60)) L.push(`| ${f.priority} ${f.severity}${f.severityKnown ? '' : '?'} | ${f.id} | ${f.package} ${f.fixed ? `(fix: ${f.fixed})` : ''} | ${f.location} | ${String(f.title).replace(/\|/g, '/').slice(0, 120)} |`);
    if (sorted.length > 60) L.push(`| ... | ${sorted.length - 60} more in report.json | | | |`);
  }
  for (const r of results) if (r.suppressed.length) { L.push('', `## ${r.tool} suppressed`, ''); for (const f of r.suppressed) L.push(`- ${f.id} ${f.package} - ${f.suppressedBy} (until ${f.until})`); }
  if (ignores.invalid.length) { L.push('', '## Ignored suppression entries', ''); for (const e of ignores.invalid) L.push(`- ${e.tool || '*'} ${e.id || '(no id)'}: ${e.why}`); }
  L.push('', '`severity?` = the tool gave no usable severity, treated as medium.');
  fs.writeFileSync(path.join(ctx.out, 'report.md'), L.join('\n') + '\n');
}

// ------------------------------------------------------------------ main
function parseArgs(argv) {
  const o = { root: process.cwd(), out: '', failOn: 'high', only: [], skip: [], ignore: '', semgrepConfigs: [], excludes: [], preflight: false, noPublish: false, keep: false, noHistory: false, help: false };
  const val = (i) => { if (i + 1 >= argv.length) throw new Error(`${argv[i]} needs a value`); return argv[i + 1]; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--root') o.root = val(i++); else if (a === '--out') o.out = val(i++);
    else if (a === '--fail-on') o.failOn = val(i++).toLowerCase();
    else if (a === '--only') o.only = val(i++).split(',').filter(Boolean); else if (a === '--skip') o.skip = val(i++).split(',').filter(Boolean);
    else if (a === '--ignore') o.ignore = val(i++);
    else if (a === '--semgrep-config') o.semgrepConfigs.push(val(i++)); else if (a === '--exclude') o.excludes.push(val(i++));
    else if (a === '--preflight') o.preflight = true; else if (a === '--no-publish') o.noPublish = true;
    else if (a === '--keep') o.keep = true; else if (a === '--no-history') o.noHistory = true; else if (a === '--no-pdf') o.noPdf = true;
    else if (a === '--help' || a === '-h') o.help = true; else throw new Error(`unknown argument ${a}`);
  }
  if (!SEV[o.failOn]) throw new Error('--fail-on must be critical, high, medium or low');
  for (const t of [...o.only, ...o.skip]) if (!TOOLS.includes(t)) throw new Error(`unknown tool "${t}" (valid: ${TOOLS.join(', ')})`);
  return o;
}
const HELP = `security-gate: gitleaks + nuget + semgrep + osv + grype -> one verdict
  node gate.mjs [--root <dir>] [--out <dir>] [--fail-on critical|high|medium|low]
                [--only a,b] [--skip a,b] [--preflight] [--no-publish] [--no-history] [--no-pdf]
                [--ignore <file>] [--semgrep-config <cfg>]... [--exclude <glob>]... [--keep]
  tools: ${TOOLS.join(', ')}    exit: 0 PASS, 1 FAIL, 2 INCOMPLETE/usage`;

function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`error: ${e.message}\n${HELP}`); return 2; }
  if (opts.help) { console.log(HELP); return 0; }
  const root = path.resolve(opts.root);
  const out = path.resolve(root, opts.out || path.join('.work', 'security-gate'));
  const selected = TOOLS.filter((t) => (!opts.only.length || opts.only.includes(t)) && !opts.skip.includes(t));
  const skipped = TOOLS.filter((t) => !selected.includes(t));

  const info = Object.fromEntries(selected.map((t) => [t, detect(t)]));
  const dotnetDetected = info.nuget || detect('nuget');
  if (opts.preflight) {
    console.log('Tool preflight (nothing is installed by this script):');
    let missing = 0;
    for (const t of TOOLS) {
      const d = info[t] || detect(t);
      if (!d.found) missing++;
      console.log(`  ${t.padEnd(9)} ${d.found ? 'OK       ' + d.version : 'MISSING  -> ' + INSTALL[t]}`);
    }
    console.log(`Local tools folder: ${TOOLS_DIR} ${LOCAL_DIRS.length ? '(in use)' : '(not present, using system PATH)'}`);
    console.log('Network needed: semgrep downloads rule packs, grype downloads its vulnerability DB on first run (large), NuGet audit queries nuget.org.');
    console.log('After a winget/pip install, open a NEW terminal so PATH is refreshed.');
    return missing ? 2 : 0;
  }

  fs.mkdirSync(out, { recursive: true }); // created only for a real run (preflight writes nothing)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'security-gate-'));
  const ctx = { root, out, tmp, opts, versions: Object.fromEntries(selected.map((t) => [t, info[t].version])), dotnet: findDotnetTargets(root), pub: [] };
  const extraNotes = [];
  try {
    // publish only when osv-scanner or grype is actually installed (otherwise it is wasted work)
    if ((info.osv?.found || info.grype?.found) && !opts.noPublish && ctx.dotnet.projects.length) {
      if (dotnetDetected.found) {
        console.log('Publishing .NET projects to a temp folder so osv-scanner/grype can read deps.json ...');
        const p = publishDotnet(ctx); ctx.pub = p.pub; extraNotes.push(...p.notes);
      } else extraNotes.push('dotnet not found: osv/grype cannot see NuGet dependencies (no publish output)');
    }
    const results = [];
    for (const t of selected) {
      if (!info[t].found) { results.push({ tool: t, status: 'NOT-RUN', findings: [], note: `not installed. Install: ${INSTALL[t]}`, version: '', seconds: 0 }); continue; }
      console.log(`Running ${t} ...`);
      const t0 = Date.now();
      let r; try { r = RUNNERS[t](ctx); } catch (e) { r = { status: 'ERROR', findings: [], note: `runner crashed: ${e.message}` }; }
      results.push({ tool: t, version: info[t].version, seconds: Math.round((Date.now() - t0) / 1000), ...r });
    }
    // suppressions
    let entries = [];
    const ignoreFile = path.resolve(root, opts.ignore || path.join('.security-gate', 'ignore.json'));
    if (fs.existsSync(ignoreFile)) { try { entries = JSON.parse(fs.readFileSync(ignoreFile, 'utf8')).ignore || []; } catch (e) { extraNotes.push(`ignore file unreadable: ${e.message}`); } }
    const invalid = applyIgnores([], entries).invalid; // validity does not depend on a tool
    for (const r of results) {
      const a = applyIgnores(r.findings, entries);
      r.findings = a.active; r.suppressed = a.suppressed;
    }
    const ev = evaluate(results, opts.failOn, skipped);
    writeReports(ctx, results, ev, skipped, { invalid }, extraNotes);
    let pdf = null;
    if (!opts.noPdf) { try { pdf = buildPdf(path.join(out, 'report.json'), path.join(out, 'security-report.pdf'), path.basename(root)); } catch (e) { pdf = { ok: false, file: '', note: e.message }; } }

    console.log('\nSecurity gate result (fail on ' + opts.failOn + '+):');
    for (const r of results) console.log(`  ${r.tool.padEnd(9)} ${String(r.final).padEnd(12)} blocking=${r.blocking.length} below=${r.belowThreshold} suppressed=${r.suppressed.length}  ${r.note ? '- ' + String(r.note).slice(0, 140) : ''}`);
    for (const s of skipped) console.log(`  ${s.padEnd(9)} SKIPPED      (gate incomplete)`);
    for (const n of extraNotes) console.log(`  note: ${n.slice(0, 200)}`);
    console.log(`\nVERDICT: ${ev.verdict}   report: ${path.relative(process.cwd(), path.join(out, 'report.md'))}`);
    if (pdf) console.log(pdf.ok ? `PDF report: ${pdf.file}` : `PDF not created (${pdf.note}) html: ${pdf.file}`);
    return ev.exitCode;
  } finally {
    if (opts.keep) console.log(`kept temp publish output: ${tmp}`); else try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) process.exit(main());
