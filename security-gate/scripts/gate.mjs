#!/usr/bin/env node
// security-gate runner (Docker-first): OSV-Scanner + NuGet Audit (SCA), Semgrep (SAST), gitleaks (secrets),
// Trivy + Grype (container / filesystem / image), OWASP ZAP (DAST)  ->  one PASS / FAIL / INCOMPLETE verdict + PDF.
//
// Requirements: Docker Desktop, the .NET SDK (NuGet Audit + publish) and Node 20+ (this script). Nothing else is installed:
// every scanner runs in its official Docker image. Images are pulled on first use (sizes are printed; --no-pull forbids it).
// Exit codes: 0 = PASS, 1 = FAIL (blocking findings), 2 = INCOMPLETE / usage error.
// "PASS" is only printed when every selected tool really ran and nothing blocking was found.
import { spawnSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildPdf, priorityOf } from './report-pdf.mjs';

export const TOOLS = ['gitleaks', 'nuget', 'semgrep', 'osv', 'grype', 'trivy', 'zap'];
// Tool groups (same names as the team's scan.ps1): -Tool sca|sast|secrets|container|dast|all
export const GROUPS = { sca: ['nuget', 'osv'], sast: ['semgrep'], secrets: ['gitleaks'], container: ['trivy', 'grype'], dast: ['zap'] };
export const SEV = { low: 1, medium: 2, high: 3, critical: 4 };

// Official images, pinned to the versions this skill was tested with (override: SECURITY_GATE_IMAGE_<TOOL>, e.g.
// SECURITY_GATE_IMAGE_TRIVY=aquasec/trivy:latest). `bin` is prepended only when an image has no ENTRYPOINT (detected after pull).
export const IMAGES = {
  gitleaks: { image: 'ghcr.io/gitleaks/gitleaks:v8.30.1', bin: 'gitleaks', mb: 25 },
  osv: { image: 'ghcr.io/google/osv-scanner:v2.7.1', bin: 'osv-scanner', mb: null },
  grype: { image: 'anchore/grype:v0.122.0', bin: 'grype', mb: 31 },
  trivy: { image: 'aquasec/trivy:0.76.2', bin: 'trivy', mb: 60 },
  semgrep: { image: 'semgrep/semgrep:1.185.0', bin: 'semgrep', mb: 414 },
  zap: { image: 'ghcr.io/zaproxy/zaproxy:stable', bin: '', mb: 1150 },
};
const imageOf = (tool) => process.env[`SECURITY_GATE_IMAGE_${tool.toUpperCase()}`] || IMAGES[tool]?.image;

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
    env: { ...process.env, DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1', ...o.env },
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', missing: r.error?.code === 'ENOENT', timedOut: r.error?.code === 'ETIMEDOUT', error: r.error };
}
const tail = (t, n = 6) => String(t || '').trim().split(/\r?\n/).slice(-n).join(' | ').slice(0, 600);
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
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
const stripPre = (loc, pre) => { let s = String(loc); if (pre && s.startsWith(pre)) s = s.slice(pre.length); return s.replace(/^\/+/, ''); };

// ------------------------------------------------------------------ parsers (pure, unit-tested)
export function parseGitleaks(text, label = '', strip = '') {
  const arr = extractJson(text);
  if (!Array.isArray(arr)) return [];
  // Secret/Match are never copied: only rule, file, line, commit.
  return arr.map((f) => mk('gitleaks', {
    id: f.RuleID, severity: 'critical', title: f.Description || f.RuleID,
    location: `${stripPre(f.File, strip)}:${f.StartLine}` + (f.Commit ? ` @${String(f.Commit).slice(0, 8)}` : ''),
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
        const sp = String(res.source?.path || '');
        const loc = strip && sp.toLowerCase().startsWith(strip.toLowerCase()) ? sp.slice(strip.length) : path.basename(sp);
        out.push(mk('osv', {
          id, severity: sev || 'medium', severityKnown: !!sev, package: name,
          title: (pkg.package?.ecosystem === 'NuGet' && /^\d+\.\d+\.\d+\.0$/.test(String(pkg.package?.version)) ? '[assembly-version, probable false positive] ' : '') + (v.summary || ''),
          location: `${label}: ${loc}`, key: `${name}|${id}|${label}|${sp}`,
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
    const name = `${a.name}@${a.version}`;
    return mk('grype', {
      id: v.id, severity: sev || 'medium', severityKnown: !!sev, package: name,
      fixed: (v.fix?.versions || []).join(','), title: `${a.type || ''} ${v.severity || ''}`.trim(),
      location: `${label}: ${stripPre(a.locations?.[0]?.path || '', stripPrefix)}`,
      key: `${name}|${v.id}|${label}`,
    });
  });
}
// Trivy JSON: Results[].Vulnerabilities[], .Misconfigurations[] (IaC / Dockerfile) and .Secrets[] (match text is never copied).
export function parseTrivy(text, label = '') {
  const obj = extractJson(text);
  if (!obj || typeof obj !== 'object' || (obj.Results !== undefined && obj.Results !== null && !Array.isArray(obj.Results))) return null;
  const out = [];
  for (const r of obj.Results || []) {
    for (const v of r.Vulnerabilities || []) {
      const sev = normSeverity(v.Severity); const name = `${v.PkgName}@${v.InstalledVersion}`;
      out.push(mk('trivy', {
        id: v.VulnerabilityID, severity: sev || 'medium', severityKnown: !!sev, package: name, fixed: String(v.FixedVersion || '').split(',')[0].trim(),
        title: String(v.Title || '').slice(0, 160), location: `${label}: ${r.Target}`, key: `${name}|${v.VulnerabilityID}|${label}|${r.Target}`,
      }));
    }
    for (const m of r.Misconfigurations || []) {
      const sev = normSeverity(m.Severity);
      out.push(mk('trivy', {
        id: m.ID || m.AVDID, severity: sev || 'medium', severityKnown: !!sev, package: '',
        title: `[misconfiguration] ${String(m.Title || m.Message || '').slice(0, 150)}`, location: `${label}: ${r.Target}${m.CauseMetadata?.StartLine ? `:${m.CauseMetadata.StartLine}` : ''}`,
        key: `${m.ID}|${label}|${r.Target}|${m.CauseMetadata?.StartLine || ''}`,
      }));
    }
    for (const s of r.Secrets || []) {
      const sev = normSeverity(s.Severity);
      out.push(mk('trivy', {
        id: s.RuleID, severity: sev || 'high', severityKnown: !!sev, package: '',
        title: `[secret] ${String(s.Title || s.Category || '').slice(0, 120)}`, location: `${label}: ${r.Target}:${s.StartLine ?? '?'}`,
        key: `${s.RuleID}|${label}|${r.Target}|${s.StartLine}`,
      }));
    }
  }
  return out;
}
// ZAP traditional JSON report: site[].alerts[]{pluginid, alert, riskcode 0-3, instances[], solution}. Informational (0) is skipped.
export function parseZap(text) {
  const obj = extractJson(text);
  if (!obj || !Array.isArray(obj.site)) return null;
  const out = [];
  for (const s of obj.site) {
    for (const a of s.alerts || []) {
      const risk = String(a.riskcode ?? '');
      if (risk === '0') continue;
      const sev = { 3: 'high', 2: 'medium', 1: 'low' }[risk] || 'medium';
      const inst = a.instances || []; const first = inst[0]?.uri || s['@name'] || '';
      out.push(mk('zap', {
        id: `ZAP-${a.pluginid}`, severity: sev, severityKnown: !!{ 3: 1, 2: 1, 1: 1 }[risk], package: '',
        title: String(a.alert || a.name || '').slice(0, 140), location: `${first}${inst.length > 1 ? ` (+${inst.length - 1} more URLs)` : ''}`,
        solution: String(a.solution || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 240),
        key: `${a.pluginid}|${first}|${a.alert}`,
      }));
    }
  }
  return out;
}

// DAST safety: only local targets unless the user names the host explicitly.
export function checkDastTarget(url, allowHosts = []) {
  let u; try { u = new URL(url); } catch { return { ok: false, reason: `not a valid URL: ${url}` }; }
  if (!/^https?:$/.test(u.protocol)) return { ok: false, reason: 'only http(s) targets are supported' };
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const local = ['localhost', '127.0.0.1', '::1', 'host.docker.internal'].includes(host) || host.endsWith('.localhost') || host.endsWith('.test');
  if (!local && !allowHosts.map((h) => h.toLowerCase()).includes(host)) return { ok: false, reason: `refusing to scan ${host}: DAST sends real attack-style traffic. Only localhost/*.localhost/*.test by default. Add --dast-allow-host ${host} ONLY if you own or are authorised to test it.` };
  const loop = ['localhost', '127.0.0.1', '::1'].includes(host) || host.endsWith('.localhost');
  if (loop) { u.hostname = 'host.docker.internal'; } // the container reaches the host's localhost through this name
  return { ok: true, host, containerUrl: u.toString(), local };
}

// Decide whether a tool's Docker image can run. Pure so it can be unit-tested.
export function chooseRuntime({ dockerUp, imageLocal, noPull }) {
  if (!dockerUp) return 'docker-down';
  if (imageLocal) return 'docker';
  return noPull ? 'pull-needed' : 'docker';
}
// Resolve which tools to run from --tool groups / --only / --skip. zap only runs with a DAST target.
export function selectTools({ tool = ['all'], only = [], skip = [], dast = false }) {
  const set = new Set();
  const want = only.length ? only : tool.flatMap((g) => (g === 'all' ? ['sca', 'sast', 'secrets', 'container'].flatMap((x) => GROUPS[x]) : (GROUPS[g] || [g])));
  for (const t of want) set.add(t);
  if (dast) set.add('zap');
  for (const s of skip) set.delete(s);
  return TOOLS.filter((t) => set.has(t));
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

// ------------------------------------------------------------------ Docker
function dockerVersion() {
  const r = run('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 30000 });
  return r.status === 0 ? r.stdout.trim() : '';
}
function startDockerDesktop() {
  if (process.platform !== 'win32') return false;
  const exe = 'C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe';
  if (!fs.existsSync(exe)) return false;
  console.log('Docker is not running: starting Docker Desktop (up to ~3 minutes) ...');
  try { spawn(exe, [], { detached: true, stdio: 'ignore', windowsHide: true }).unref(); } catch { return false; }
  for (let i = 0; i < 36; i++) { sleep(5000); if (dockerVersion()) return true; }
  return false;
}
const imageLocal = (img) => run('docker', ['image', 'inspect', img, '--format', '{{.Id}}'], { timeout: 30000 }).status === 0;
function imageMeta(img) {
  const r = run('docker', ['image', 'inspect', img, '--format', '{{json .}}'], { timeout: 30000 });
  const j = extractJson(r.stdout) || {};
  const digest = String((j.RepoDigests || [])[0] || '').split('@')[1] || String(j.Id || '').replace('sha256:', '');
  return { digest: digest.slice(0, 19), entrypoint: j.Config?.Entrypoint || [], created: String(j.Created || '').slice(0, 10) };
}
function pullImage(img, mb) {
  console.log(`Pulling ${img} ${mb ? `(~${mb} MB) ` : ''}...`);
  return run('docker', ['pull', '-q', img], { timeout: 40 * 60 * 1000 });
}
// Inside the container: project at /src (read-only), report folder at /out, published .NET output at /pub.
const DP = { root: '/src', out: '/out', pub: (name) => `/pub/${name}` };
function toolExec(ctx, tool, args, o = {}) {
  const rt = ctx.rt[tool];
  const a = ['run', '--rm'];
  for (const [k, v] of Object.entries(o.env || {})) a.push('-e', `${k}=${v}`);
  a.push('-v', `${ctx.root}:/src:ro`, '-v', `${ctx.out}:/out`);
  if (ctx.pub.length) a.push('-v', `${path.join(ctx.tmp, 'publish')}:/pub:ro`);
  for (const v of o.volumes || []) a.push('-v', v);
  if (o.workdir) a.push('-w', o.workdir);
  a.push(rt.image, ...(rt.needsBin ? [IMAGES[tool].bin] : []), ...args);
  return run('docker', a, { timeout: o.timeout });
}

// ------------------------------------------------------------------ tool runners
function gitleaksConfig(ctx) {
  for (const f of ['.gitleaks.toml', 'gitleaks.toml']) {
    if (fs.existsSync(path.join(ctx.root, f))) return { arg: `${DP.root}/${f}`, note: `using project config ${f}` };
  }
  // gitleaks does not read .gitignore: allow-list ignored paths so gitignored secret files are not reported as repo leaks.
  const ig = run('git', ['ls-files', '--others', '--ignored', '--exclude-standard', '--directory'], { cwd: ctx.root });
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const sep = '[\\\\/]'; // regex class: backslash or slash
  const paths = (ig.status === 0 ? ig.stdout.split(/\r?\n/).filter(Boolean) : [])
    .map((p) => `(^|${sep})${esc(p.replace(/\/$/, '')).replace(/\//g, sep)}(${sep}|$)`);
  paths.push(`(^|${sep})(node_modules|bin|obj|\\.git)${sep}`);
  fs.writeFileSync(path.join(ctx.out, 'gitleaks.config.toml'), `[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "gitignored and generated paths"\npaths = [\n${paths.map((p) => `  '''${p}'''`).join(',\n')}\n]\n`);
  return { arg: `${DP.out}/gitleaks.config.toml`, note: `${paths.length} ignored paths allow-listed` };
}
function runGitleaks(ctx) {
  const cfg = gitleaksConfig(ctx);
  const base = ['--config', cfg.arg, '--redact', '--no-banner', '--exit-code', '2', '-f', 'json'];
  const findings = []; const notes = [cfg.note];
  const scans = [['dir', 'gitleaks-dir.json', 'working tree']];
  const hasCommits = run('git', ['rev-parse', '--verify', 'HEAD'], { cwd: ctx.root }).status === 0;
  if (!ctx.opts.noHistory) {
    if (hasCommits) scans.push(['git', 'gitleaks-git.json', 'git history']);
    else notes.push('git history: repository has no commits yet (nothing to scan)');
  }
  const env = { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'safe.directory', GIT_CONFIG_VALUE_0: '/src' }; // read-only mount owned by another uid
  for (const [mode, name, label] of scans) {
    const report = path.join(ctx.out, name);
    try { fs.rmSync(report, { force: true }); } catch { /* ignore */ }
    const r = toolExec(ctx, 'gitleaks', [mode, ...base, '-r', `${DP.out}/${name}`, DP.root], { timeout: 15 * 60 * 1000, env });
    if (r.status !== 0 && r.status !== 2) return { status: 'ERROR', note: `gitleaks ${mode} failed (exit ${r.status}): ${tail(r.stderr || r.stdout)}`, findings: [] };
    let text = '[]'; try { text = fs.readFileSync(report, 'utf8'); } catch { if (r.status === 2) return { status: 'ERROR', note: `gitleaks ${mode} reported leaks but wrote no report`, findings: [] }; }
    findings.push(...parseGitleaks(text, label, `${DP.root}/`));
    notes.push(`${label}: scanned`);
  }
  return { status: 'OK', findings: dedupe(findings), note: notes.join('; ') };
}
function runNuget(ctx) {
  const { targets } = ctx.dotnet;
  if (!targets.length) return { status: 'N/A', findings: [], note: 'no .sln/.slnx/.csproj found - not a .NET repository' };
  const major = parseInt(String(ctx.dotnetVersion).split('.')[0], 10);
  if (!(major >= 8)) return { status: 'ERROR', findings: [], note: `needs .NET SDK 8+ for "dotnet list package --format json" (found ${ctx.dotnetVersion || 'none'})` };
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
  const args = ['scan', '--metrics=off', '--json', '--json-output', `${DP.out}/semgrep.json`, '--quiet', '--disable-version-check'];
  for (const c of configs) args.push('--config', c);
  for (const e of [...NOISE_EXCLUDES, ...SECRET_EXCLUDES, ...ctx.opts.excludes]) args.push('--exclude', e);
  args.push('.');
  const r = toolExec(ctx, 'semgrep', args, { timeout: 30 * 60 * 1000, workdir: DP.root });
  let text = ''; try { text = fs.readFileSync(report, 'utf8'); } catch { /* none */ }
  const findings = r.status !== null && r.status < 2 ? parseSemgrep(text) : null;
  if (!findings) return { status: 'ERROR', findings: [], note: `semgrep failed (exit ${r.status}): ${tail(r.stderr || r.stdout)}` };
  const errs = (extractJson(text)?.errors || []).length;
  return { status: 'OK', findings, note: `rulesets: ${configs.join(', ')}${errs ? `; ${errs} files/rules had scan errors (see semgrep.json)` : ''}` };
}
// OSV-Scanner is pointed at each top-level project folder (not the repo root) so dot-folders such as .claude, .git
// and .work (tooling, not product code) are never scanned; the same folders semgrep, grype and trivy exclude.
const OSV_ROOT_FILES = /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|packages\.lock\.json|requirements\.txt|poetry\.lock|go\.mod|Cargo\.lock|composer\.lock|Gemfile\.lock|pom\.xml)$/i;
function osvTargets(ctx) {
  const out = []; let entries = [];
  try { entries = fs.readdirSync(ctx.root, { withFileTypes: true }); } catch { /* none */ }
  for (const e of entries) {
    if (e.isDirectory()) { if (!e.name.startsWith('.') && !['node_modules', 'bin', 'obj'].includes(e.name)) out.push({ label: `repo/${e.name}`, args: ['-r', `${DP.root}/${e.name}`], strip: `${DP.root}/` }); }
    else if (OSV_ROOT_FILES.test(e.name)) out.push({ label: `repo/${e.name}`, args: ['-L', `${DP.root}/${e.name}`], strip: `${DP.root}/` });
  }
  for (const p of ctx.pub) out.push({ label: `published:${p.name}`, args: ['-r', DP.pub(p.name)], strip: `${DP.pub(p.name)}/` });
  return out;
}
function runOsv(ctx) {
  const findings = []; const scanned = []; const empty = [];
  for (const t of osvTargets(ctx)) {
    const r = toolExec(ctx, 'osv', ['scan', 'source', ...t.args, '--format', 'json'], { timeout: 15 * 60 * 1000 });
    if (r.status === 128) { empty.push(t.label); continue; } // "no packages found"
    if (r.status !== 0 && r.status !== 1) return { status: 'ERROR', findings: [], note: `osv-scanner failed on ${t.label} (exit ${r.status}): ${tail(r.stderr || r.stdout)}` };
    fs.writeFileSync(path.join(ctx.out, `osv-${t.label.replace(/[^\w.-]/g, '_')}.json`), r.stdout);
    const f = parseOsv(r.stdout, t.label, t.strip);
    if (!f) return { status: 'ERROR', findings: [], note: `osv-scanner output for ${t.label} was not valid JSON` };
    findings.push(...f); scanned.push(t.label);
  }
  if (!scanned.length) return { status: 'NO-COVERAGE', findings: [], note: `no lockfiles/manifests found in: ${empty.join(', ') || 'repo'}${ctx.dotnet.targets.length && !ctx.pub.length ? ' (.NET deps need a publish output; see references/tools.md)' : ''}` };
  return { status: 'OK', findings: dedupe(findings), note: `scanned: ${scanned.join(', ')}${empty.length ? `; no packages in ${empty.length} other target(s)` : ''}` };
}
// Container images: a locally built image is scanned through the Docker socket (like the team's scan.ps1); otherwise from the registry.
const SOCK = '/var/run/docker.sock:/var/run/docker.sock';
function runGrype(ctx) {
  const targets = [{ label: 'repo', src: `dir:${DP.root}`, excl: true }, ...ctx.pub.map((p) => ({ label: `published:${p.name}`, src: `dir:${DP.pub(p.name)}`, prefix: `${DP.pub(p.name)}/` })),
    ...ctx.opts.images.map((i) => ({ label: `image:${i}`, local: imageLocal(i), ref: i }))];
  const findings = [];
  for (const t of targets) {
    const src = t.ref ? (t.local ? `docker:${t.ref}` : `registry:${t.ref}`) : t.src;
    const args = [src, '-o', 'json', '-q'];
    if (t.excl) for (const g of NOISE_EXCLUDES) args.push('--exclude', `./**/${g}/**`);
    const r = toolExec(ctx, 'grype', args, { timeout: 40 * 60 * 1000, env: { GRYPE_DB_CACHE_DIR: '/db' }, volumes: ['security-gate-grype-db:/db', ...(t.local ? [SOCK] : [])] });
    if (r.status !== 0) return { status: 'ERROR', findings: [], note: `grype failed on ${t.label} (exit ${r.status}): ${tail(r.stderr || r.stdout)}` };
    fs.writeFileSync(path.join(ctx.out, `grype-${t.label.replace(/[^\w.-]/g, '_')}.json`), r.stdout);
    const f = parseGrype(r.stdout, t.label, t.prefix || '');
    if (!f) return { status: 'ERROR', findings: [], note: `grype output for ${t.label} was not valid JSON` };
    findings.push(...f);
  }
  return { status: 'OK', findings: dedupe(findings), note: `scanned: ${targets.map((t) => t.label).join(', ')}` };
}
// Trivy: dependencies, IaC/Dockerfile misconfigurations and secrets in the source tree; vulnerabilities in container images.
function runTrivy(ctx) {
  const skip = NOISE_EXCLUDES.flatMap((g) => ['--skip-dirs', `**/${g}`]);
  const targets = [{ label: 'repo', kind: 'fs', ref: DP.root, skip: true }, ...ctx.pub.map((p) => ({ label: `published:${p.name}`, kind: 'fs', ref: DP.pub(p.name) })),
    ...ctx.opts.images.map((i) => ({ label: `image:${i}`, kind: 'image', ref: i, local: imageLocal(i) }))];
  const findings = [];
  for (const t of targets) {
    const name = `trivy-${t.label.replace(/[^\w.-]/g, '_')}.json`;
    const report = path.join(ctx.out, name);
    try { fs.rmSync(report, { force: true }); } catch { /* ignore */ }
    const args = [t.kind, '--format', 'json', '--output', `${DP.out}/${name}`, '--quiet', '--cache-dir', '/cache',
      '--scanners', t.kind === 'fs' ? (t.skip ? 'vuln,misconfig,secret' : 'vuln') : 'vuln', ...(t.skip ? skip : []),
      ...(t.kind === 'image' ? ['--image-src', t.local ? 'docker' : 'remote'] : []), t.ref];
    const r = toolExec(ctx, 'trivy', args, { timeout: 40 * 60 * 1000, volumes: ['security-gate-trivy-cache:/cache', ...(t.local ? [SOCK] : [])] });
    if (r.status !== 0) return { status: 'ERROR', findings: [], note: `trivy failed on ${t.label} (exit ${r.status}): ${tail(r.stderr || r.stdout)}` };
    let text = ''; try { text = fs.readFileSync(report, 'utf8'); } catch { /* none */ }
    const f = parseTrivy(text, t.label);
    if (!f) return { status: 'ERROR', findings: [], note: `trivy output for ${t.label} was not valid JSON` };
    findings.push(...f);
  }
  return { status: 'OK', findings: dedupe(findings), note: `scanned: ${targets.map((t) => t.label).join(', ')} (vulnerabilities, IaC misconfigurations, secrets)` };
}
// OWASP ZAP (DAST). Baseline = passive scan (safe). Full = active attacks, needs explicit confirmation.
function runZap(ctx) {
  const o = ctx.opts;
  const chk = checkDastTarget(o.dastUrl, o.dastAllow);
  if (!chk.ok) return { status: 'ERROR', findings: [], note: chk.reason };
  const script = o.dastFull ? 'zap-full-scan.py' : 'zap-baseline.py';
  const report = path.join(ctx.out, 'zap.json');
  try { fs.rmSync(report, { force: true }); } catch { /* ignore */ }
  const a = ['run', '--rm', '--add-host', 'host.docker.internal:host-gateway', '-v', `${ctx.out}:/zap/wrk:rw`, ctx.rt.zap.image,
    script, '-t', chk.containerUrl, '-J', 'zap.json', '-r', 'zap.html', '-I', '-m', String(o.dastMinutes)];
  const r = run('docker', a, { timeout: 60 * 60 * 1000 });
  let text = ''; try { text = fs.readFileSync(report, 'utf8'); } catch { /* none */ }
  const findings = r.status !== null && r.status <= 2 ? parseZap(text) : null;
  if (!findings) return { status: 'ERROR', findings: [], note: `zap failed (exit ${r.status}); is ${o.dastUrl} up? ${tail(r.stderr || r.stdout)}` };
  return { status: 'OK', findings: dedupe(findings), note: `${o.dastFull ? 'ACTIVE full scan' : 'passive baseline scan'} of ${o.dastUrl} (${o.dastMinutes} min spider)` };
}
const RUNNERS = { gitleaks: runGitleaks, nuget: runNuget, semgrep: runSemgrep, osv: runOsv, grype: runGrype, trivy: runTrivy, zap: runZap };

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
  for (const r of results) if (r.version) L.push('', `> ${r.tool}: ${r.version}`);
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
  const o = { root: process.cwd(), out: '', failOn: 'high', tool: ['all'], only: [], skip: [], ignore: '', semgrepConfigs: [], excludes: [], images: [], dastUrl: '', dastAllow: [], dastFull: false, dastConfirm: false, dastMinutes: 1,
    noPull: false, preflight: false, noPublish: false, keep: false, noHistory: false, noPdf: false, help: false };
  const val = (i) => { if (i + 1 >= argv.length) throw new Error(`${argv[i]} needs a value`); return argv[i + 1]; };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--root') o.root = val(i++); else if (a === '--out') o.out = val(i++);
    else if (a === '--fail-on') o.failOn = val(i++).toLowerCase();
    else if (a === '--tool') o.tool = list(val(i++)); else if (a === '--only') o.only = list(val(i++)); else if (a === '--skip') o.skip = list(val(i++));
    else if (a === '--ignore') o.ignore = val(i++);
    else if (a === '--semgrep-config') o.semgrepConfigs.push(val(i++)); else if (a === '--exclude') o.excludes.push(val(i++));
    else if (a === '--image') o.images.push(val(i++));
    else if (a === '--dast-url') o.dastUrl = val(i++); else if (a === '--dast-allow-host') o.dastAllow.push(val(i++));
    else if (a === '--dast-full') o.dastFull = true; else if (a === '--i-am-authorized') o.dastConfirm = true;
    else if (a === '--dast-minutes') o.dastMinutes = Math.max(1, parseInt(val(i++), 10) || 1);
    else if (a === '--no-pull') o.noPull = true;
    else if (a === '--preflight') o.preflight = true; else if (a === '--no-publish') o.noPublish = true;
    else if (a === '--keep') o.keep = true; else if (a === '--no-history') o.noHistory = true; else if (a === '--no-pdf') o.noPdf = true;
    else if (a === '--help' || a === '-h') o.help = true; else throw new Error(`unknown argument ${a}`);
  }
  if (!SEV[o.failOn]) throw new Error('--fail-on must be critical, high, medium or low');
  for (const t of [...o.only, ...o.skip]) if (!TOOLS.includes(t)) throw new Error(`unknown tool "${t}" (valid: ${TOOLS.join(', ')})`);
  for (const g of o.tool) if (g !== 'all' && !GROUPS[g]) throw new Error(`unknown --tool "${g}" (valid: all, ${Object.keys(GROUPS).join(', ')})`);
  if ((o.tool.includes('dast') || o.only.includes('zap')) && !o.dastUrl) throw new Error('DAST needs --dast-url <http://localhost:PORT> (the app must be running)');
  if (o.dastFull && !o.dastConfirm) throw new Error('--dast-full sends ACTIVE attack traffic; add --i-am-authorized only if you own or are authorised to test the target');
  return o;
}
const HELP = `security-gate (Docker-first): sca + sast + secrets + container (+ dast) -> one verdict + PDF
  node gate.mjs [--root <dir>] [--out <dir>] [--fail-on critical|high|medium|low]
                [--tool all|sca|sast|secrets|container|dast[,..]]  [--only a,b] [--skip a,b]
                [--image <ref>]...                       scan a container image (local image via the Docker socket)
                [--dast-url <url> [--dast-full --i-am-authorized] [--dast-allow-host <h>] [--dast-minutes n]]
                [--preflight] [--no-pull] [--no-publish] [--no-history] [--no-pdf]
                [--ignore <file>] [--semgrep-config <cfg>]... [--exclude <glob>]... [--keep]
  groups: sca = nuget + osv, sast = semgrep, secrets = gitleaks, container = trivy + grype, dast = zap
  needs : Docker Desktop (started automatically on Windows), .NET SDK (for nuget), Node 20+
  images: pulled on first use (sizes printed; --no-pull forbids it); versions pinned, override with SECURITY_GATE_IMAGE_<TOOL>
  exit  : 0 PASS, 1 FAIL, 2 INCOMPLETE/usage`;

function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`error: ${e.message}\n${HELP}`); return 2; }
  if (opts.help) { console.log(HELP); return 0; }
  const root = path.resolve(opts.root);
  const out = path.resolve(root, opts.out || path.join('.work', 'security-gate'));
  const selected = selectTools({ tool: opts.tool, only: opts.only, skip: opts.skip, dast: !!opts.dastUrl });
  const wanted = selectTools({ tool: ['all'], only: [], skip: [], dast: !!opts.dastUrl });
  // --skip makes the gate INCOMPLETE; a deliberate scope (--tool / --only) is reported as a partial scan instead.
  const skipped = opts.skip.filter((t) => wanted.includes(t));
  const outOfScope = wanted.filter((t) => !selected.includes(t) && !opts.skip.includes(t));
  const dotnet = run('dotnet', ['--version'], { timeout: 30000 });
  const dotnetVersion = dotnet.status === 0 ? dotnet.stdout.trim() : '';

  let dVer = dockerVersion();
  const needsDocker = selected.some((t) => IMAGES[t]) || opts.preflight;
  if (!dVer && needsDocker && !opts.preflight) { if (startDockerDesktop()) dVer = dockerVersion(); }
  const rt = {};
  for (const t of TOOLS) {
    if (!IMAGES[t]) { rt[t] = { mode: t === 'nuget' ? (dotnetVersion ? 'dotnet' : 'missing') : 'missing', version: dotnetVersion }; continue; }
    const img = imageOf(t);
    const choice = chooseRuntime({ dockerUp: !!dVer, imageLocal: !!dVer && imageLocal(img), noPull: opts.noPull });
    rt[t] = { mode: choice === 'docker' ? 'docker' : 'missing', choice, image: img, version: '' };
  }
  const missingReason = (t) => {
    if (t === 'nuget') return 'the .NET SDK 8+ is not installed (https://dotnet.microsoft.com/download)';
    const c = rt[t].choice;
    if (c === 'docker-down') return 'Docker is not running and could not be started. Start Docker Desktop and retry';
    if (c === 'pull-needed') return `image ${rt[t].image} (~${IMAGES[t].mb ?? '?'} MB) is not pulled and --no-pull was given`;
    return rt[t].pullError ? `could not pull ${rt[t].image}: ${rt[t].pullError}` : 'tool unavailable';
  };

  if (opts.preflight) {
    console.log('Preflight (nothing is pulled or installed by --preflight):');
    console.log(`  docker    ${dVer ? 'OK       engine ' + dVer : 'NOT RUNNING  (it is started automatically on a real run on Windows)'}`);
    console.log(`  dotnet    ${dotnetVersion ? 'OK       SDK ' + dotnetVersion : 'MISSING  -> install the .NET SDK 8+ (needed for NuGet Audit and publish)'}`);
    let problems = dotnetVersion ? 0 : 1;
    for (const t of ['gitleaks', 'semgrep', 'osv', 'grype', 'trivy', 'zap']) {
      const local = dVer && imageLocal(imageOf(t));
      console.log(`  ${t.padEnd(9)} ${local ? 'OK       image ready ' + imageOf(t) : `will pull ${imageOf(t)} (~${IMAGES[t].mb ?? '?'} MB) on first use${t === 'zap' ? ' (only for --dast-url)' : ''}`}`);
    }
    if (!dVer) problems++;
    console.log('Network needed on first run: image pulls, Semgrep rules, Trivy/Grype databases, nuget.org.');
    return problems ? 2 : 0;
  }

  fs.mkdirSync(out, { recursive: true }); // created only for a real run (preflight writes nothing)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'security-gate-'));
  const ctx = { root, out, tmp, opts, rt, dotnet: findDotnetTargets(root), dotnetVersion, pub: [] };
  const extraNotes = [];
  if (outOfScope.length) extraNotes.push(`Partial scan by request: ${outOfScope.join(', ')} not run. This verdict covers only: ${selected.join(', ')}.`);
  try {
    // pull / inspect the images that will be used
    for (const t of selected) {
      if (!IMAGES[t] || rt[t].mode !== 'docker') continue;
      if (!imageLocal(rt[t].image)) {
        const p = pullImage(rt[t].image, IMAGES[t].mb);
        if (p.status !== 0) { rt[t] = { ...rt[t], mode: 'missing', choice: 'pull-failed', pullError: tail(p.stderr || p.stdout) }; continue; }
      }
      const meta = imageMeta(rt[t].image);
      rt[t].needsBin = t !== 'zap' && (!meta.entrypoint || meta.entrypoint.length === 0);
      rt[t].version = `${rt[t].image} ${meta.digest}${meta.created ? ` (built ${meta.created})` : ''}`;
    }
    // publish only when a dependency scanner will run (otherwise it is wasted work)
    const depTools = ['osv', 'grype', 'trivy'].filter((t) => selected.includes(t) && rt[t].mode === 'docker');
    if (depTools.length && !opts.noPublish && ctx.dotnet.projects.length) {
      if (dotnetVersion) {
        console.log('Publishing .NET projects to a temp folder so the dependency scanners can read deps.json ...');
        const p = publishDotnet(ctx); ctx.pub = p.pub; extraNotes.push(...p.notes);
      } else extraNotes.push('dotnet not found: dependency scanners cannot see NuGet dependencies (no publish output)');
    }
    const results = [];
    for (const t of selected) {
      if (rt[t].mode === 'missing') { results.push({ tool: t, status: 'NOT-RUN', findings: [], note: missingReason(t), version: '', seconds: 0 }); continue; }
      console.log(`Running ${t} ...`);
      const t0 = Date.now();
      let r; try { r = RUNNERS[t](ctx); } catch (e) { r = { status: 'ERROR', findings: [], note: `runner crashed: ${e.message}` }; }
      results.push({ tool: t, version: rt[t].version, seconds: Math.round((Date.now() - t0) / 1000), ...r });
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
    for (const r of results) console.log(`  ${r.tool.padEnd(9)} ${String(r.final).padEnd(12)} blocking=${r.blocking.length} below=${r.belowThreshold} suppressed=${r.suppressed.length}  ${r.note ? '- ' + String(r.note).slice(0, 130) : ''}`);
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
