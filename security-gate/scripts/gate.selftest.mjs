// Offline self-test for gate.mjs parsers and verdict logic. No scanner needed.
// Run: node .claude/skills/security-gate/scripts/gate.selftest.mjs
// NOTE: fixtures follow the documented output of each tool. They prove the gate logic, not that a
// given scanner version still prints exactly this shape; the first real run of each tool confirms that.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectApp, startApp, freePort } from './app-start.mjs';
import { parseIgnoredList, looksLikeGuidOnly, semgrepRulesets, detectLanguages, parseGitleaks, parseDotnetList, parseSemgrep, parseOsv, parseGrype, parseTrivy, parseZap, checkDastTarget, chooseRuntime, selectTools, applyIgnores, evaluate, extractJson, cvssToSeverity } from './gate.mjs';

let n = 0; const t = (name, fn) => { fn(); n++; console.log('ok  ' + name); };

t('extractJson skips a banner before JSON', () => assert.deepEqual(extractJson('warn: x\n{"a":1}'), { a: 1 }));
t('cvss mapping', () => { assert.equal(cvssToSeverity('9.8'), 'critical'); assert.equal(cvssToSeverity('7.5'), 'high'); assert.equal(cvssToSeverity('5'), 'medium'); assert.equal(cvssToSeverity('2'), 'low'); assert.equal(cvssToSeverity(''), null); });

t('gitleaks: never copies the secret', () => {
  const f = parseGitleaks(JSON.stringify([{ RuleID: 'aws-access-token', Description: 'key', File: 'a/b.cs', StartLine: 7, Secret: 'REDACTED', Match: 'REDACTED', Commit: 'abcdef123456', Fingerprint: 'fp1' }]));
  assert.equal(f.length, 1); assert.equal(f[0].severity, 'critical'); assert.equal(f[0].location, 'a/b.cs:7 @abcdef12');
  assert.ok(!JSON.stringify(f).includes('REDACTED'));
});

t('gitleaks: generic rule is High, GUID-only line is Low + labelled, real-looking value stays High', () => {
  const hit = (RuleID, File, StartLine) => ({ RuleID, Description: 'd', File, StartLine, Fingerprint: `${File}:${StartLine}` });
  const lines = { 'a.config': ['<Key>3f2504e0-4f89-41d3-9a0c-0305e82c3301</Key>'], 'b.cs': ['var k = "Zk9fQ2xpZW50U2VjcmV0MTIzNDU2Nzg5MA";'] };
  const f = parseGitleaks(JSON.stringify([hit('generic-api-key', 'a.config', 1), hit('generic-api-key', 'b.cs', 1), hit('aws-access-token', 'c.cs', 1)]), '', '', (rel, n) => (lines[rel] || [''])[n - 1]);
  assert.equal(f[0].severity, 'low'); assert.equal(f[0].id, 'generic-api-key:guid-like'); assert.match(f[0].title, /probable false positive/);
  assert.equal(f[1].severity, 'high'); assert.equal(f[1].id, 'generic-api-key');
  assert.equal(f[2].severity, 'critical');
  assert.equal(parseGitleaks(JSON.stringify([{ ...hit('generic-api-key', 'a.config', 1), Commit: 'abc12345' }]), '', '', () => lines['a.config'][0])[0].severity, 'high'); // history hits are never downgraded
  assert.ok(looksLikeGuidOnly('Key="3f2504e0-4f89-41d3-9a0c-0305e82c3301"')); assert.ok(!looksLikeGuidOnly('x=Zk9fQ2xpZW50U2VjcmV0MTIzNDU2 3f2504e0-4f89-41d3-9a0c-0305e82c3301')); assert.ok(!looksLikeGuidOnly('no guid here'));
});

t('dast-auto: finds out how to start .NET, Node and Django apps', () => {
  const mk = (files) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-app-')); for (const [p, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, p)), { recursive: true }); fs.writeFileSync(path.join(d, p), c); } return d; };
  const dirs = [];
  try {
    const net = mk({ 'src/Site/Site.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>', 'src/Site/Program.cs': '', 'src/Site.Tests/Site.Tests.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>', 'src/Lib/Lib.csproj': '<Project Sdk="Microsoft.NET.Sdk"></Project>' }); dirs.push(net);
    const a = detectApp(net); assert.equal(a.kind, 'dotnet'); assert.match(a.cmd, /dotnet run --project "src\/Site\/Site\.csproj" --urls http:\/\/localhost:\{port\}/); assert.equal(a.others, 1);
    const nodeNo = mk({ 'package.json': JSON.stringify({ scripts: { dev: 'next dev' }, dependencies: { next: '15' } }) }); dirs.push(nodeNo);
    const b = detectApp(nodeNo); assert.equal(b.kind, 'node'); assert.equal(b.cmd, 'npm run dev -- -p {port}'); assert.equal(b.problems.length, 1); // node_modules missing
    const nodeOk = mk({ 'package.json': JSON.stringify({ scripts: { start: 'node s.js' } }), 'node_modules/.keep': '' }); dirs.push(nodeOk);
    const c = detectApp(nodeOk); assert.equal(c.cmd, 'npm run start'); assert.equal(c.problems.length, 0);
    const dj = mk({ 'site/manage.py': '' }); dirs.push(dj);
    assert.equal(detectApp(dj).kind, 'django');
    const none = mk({ 'README.md': 'x' }); dirs.push(none);
    assert.equal(detectApp(none), null);
    const ign = mk({ 'node_modules/x/Site.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>' }); dirs.push(ign);
    assert.equal(detectApp(ign), null); // dependency folders are never searched
  } finally { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); }
});

t('dast-auto: a free port is found and an app that exits at once is reported, not hung', () => {
  assert.ok(freePort() > 0);
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-start-'));
  try {
    const r = startApp({ command: `"${process.execPath}" -e "process.exit(3)"`, cwd: d, port: freePort(), logFile: path.join(d, 'app.log'), timeoutMs: 30000 });
    assert.equal(r.ok, false); assert.match(r.note, /exited before it answered/);
  } finally { fs.rmSync(d, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 }); }
});

t('gitignore: ignored dirs and files are split from git output', () => {
  assert.deepEqual(parseIgnoredList('ignored/\r\nlocal.js\n"src/a b.env"\nbin/\n\n'), { dirs: ['ignored', 'bin'], files: ['local.js', 'src/a b.env'] });
  assert.deepEqual(parseIgnoredList(''), { dirs: [], files: [] });
});

t('semgrep: rulesets follow the languages found in the project', () => {
  const BASE = ['p/security-audit', 'p/owasp-top-ten', 'p/secrets', 'p/cwe-top-25', 'p/xss', 'p/sql-injection', 'p/command-injection', 'p/jwt', 'p/insecure-transport'];
  assert.deepEqual(semgrepRulesets(['.cs']), [...BASE, 'p/csharp']);
  assert.deepEqual(semgrepRulesets(['.ts', '.tsx', '.js'], true), [...BASE, 'p/javascript', 'p/typescript', 'p/react', 'p/dockerfile']);
  assert.deepEqual(semgrepRulesets(['.py'], false, true), [...BASE, 'p/python', 'p/django']);
  assert.deepEqual(semgrepRulesets([]), BASE);
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-lang-'));
  try {
    fs.mkdirSync(path.join(d, 'src')); fs.mkdirSync(path.join(d, 'node_modules')); fs.mkdirSync(path.join(d, '.work'));
    fs.writeFileSync(path.join(d, 'src', 'a.py'), ''); fs.writeFileSync(path.join(d, 'node_modules', 'x.js'), ''); fs.writeFileSync(path.join(d, '.work', 'y.go'), ''); fs.writeFileSync(path.join(d, 'Dockerfile'), '');
    const r = detectLanguages(d); assert.deepEqual(r.exts, ['.py']); assert.equal(r.dockerfile, true);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

t('nuget: severities, transitive, dedupe, problems', () => {
  const j = { version: 1, problems: [{ level: 'warning', text: 'x' }], projects: [{ path: 'C:/x/Web.csproj', frameworks: [{ framework: 'net10.0',
    topLevelPackages: [{ id: 'Foo', resolvedVersion: '1.0.0', vulnerabilities: [{ severity: 'High', advisoryurl: 'https://github.com/advisories/GHSA-aaaa' }] }],
    transitivePackages: [{ id: 'Bar', resolvedVersion: '2.0.0', vulnerabilities: [{ severity: 'Moderate', advisoryurl: 'https://github.com/advisories/GHSA-bbbb' }] }] }] },
  { path: 'C:/x/Core.csproj', frameworks: [{ framework: 'net10.0', topLevelPackages: [{ id: 'Foo', resolvedVersion: '1.0.0', vulnerabilities: [{ severity: 'High', advisoryurl: 'https://github.com/advisories/GHSA-aaaa' }] }] }] }] };
  const r = parseDotnetList('Restoring...\n' + JSON.stringify(j));
  assert.equal(r.findings.length, 2); assert.equal(r.findings.find((f) => f.package === 'Bar@2.0.0').severity, 'medium'); assert.equal(r.findings[0].id, 'GHSA-aaaa');
});

t('semgrep: maps severity, drops code lines', () => {
  const f = parseSemgrep(JSON.stringify({ results: [{ check_id: 'r1', path: 'x.cs', start: { line: 3 }, extra: { severity: 'ERROR', message: 'bad', lines: 'password="hunter2"' } }, { check_id: 'r2', path: 'y.cs', start: { line: 1 }, extra: { severity: 'INFO', message: 'meh' } }] }));
  assert.equal(f[0].severity, 'high'); assert.equal(f[1].severity, 'low'); assert.ok(!JSON.stringify(f).includes('hunter2'));
  assert.equal(parseSemgrep('not json'), null);
});

t('osv: group max_severity, CVE alias preferred, unknown flagged', () => {
  const j = { results: [{ source: { path: '/p/web.deps.json', type: 'lockfile' }, packages: [{ package: { name: 'Foo', version: '1.0', ecosystem: 'NuGet' },
    vulnerabilities: [{ id: 'GHSA-1', aliases: ['CVE-2024-1'], summary: 's' }, { id: 'GHSA-2', summary: 'u' }],
    groups: [{ ids: ['GHSA-1', 'CVE-2024-1'], max_severity: '9.1' }, { ids: ['GHSA-2'] }] }] }] };
  const f = parseOsv(JSON.stringify(j), 'repo');
  assert.equal(f.length, 2); assert.equal(f[0].id, 'CVE-2024-1'); assert.equal(f[0].severity, 'critical');
  assert.equal(f[1].severity, 'medium'); assert.equal(f[1].severityKnown, false);
});

t('grype: severity, fix versions, path prefix stripped', () => {
  const j = { matches: [{ vulnerability: { id: 'CVE-1', severity: 'Critical', fix: { versions: ['2.0'] } }, artifact: { name: 'Foo', version: '1.0', type: 'dotnet', locations: [{ path: '/tmp/pub/web.deps.json' }] } }, { vulnerability: { id: 'CVE-2', severity: 'Negligible' }, artifact: { name: 'Bar', version: '1', locations: [] } }] };
  const f = parseGrype(JSON.stringify(j), 'published:web', '/tmp/pub/');
  assert.equal(f[0].severity, 'critical'); assert.equal(f[0].fixed, '2.0'); assert.equal(f[0].location, 'published:web: web.deps.json'); assert.equal(f[1].severity, 'low');
});

t('suppressions need reason + future expiry', () => {
  const fs = [{ tool: 'grype', id: 'CVE-1', package: 'Foo@1', location: '' }, { tool: 'grype', id: 'CVE-2', package: 'Bar@1', location: '' }, { tool: 'osv', id: 'CVE-1', package: 'Foo@1', location: '' }];
  const a = applyIgnores(fs, [{ tool: 'grype', id: 'CVE-1', reason: 'not reachable, fixed next sprint', expires: '2099-01-01' }, { tool: 'grype', id: 'CVE-2', reason: 'old', expires: '2000-01-01' }, { id: 'CVE-9', reason: '', expires: '2099-01-01' }]);
  assert.equal(a.suppressed.length, 1); assert.equal(a.active.length, 2); assert.equal(a.invalid.length, 2);
});

t('verdict: PASS only when everything ran and is clean', () => {
  const ok = (tool, findings = []) => ({ tool, status: 'OK', findings });
  const f = (severity) => ({ severity });
  assert.equal(evaluate([ok('a'), ok('b', [f('medium')])], 'high').verdict, 'PASS');
  assert.equal(evaluate([ok('a'), ok('b', [f('high')])], 'high').verdict, 'FAIL');
  assert.equal(evaluate([ok('a'), { tool: 'b', status: 'NOT-RUN', findings: [] }], 'high').verdict, 'INCOMPLETE');
  assert.equal(evaluate([ok('a'), { tool: 'b', status: 'NO-COVERAGE', findings: [] }], 'high').verdict, 'INCOMPLETE');
  assert.equal(evaluate([ok('a'), { tool: 'b', status: 'N/A', findings: [] }], 'high').verdict, 'PASS');
  assert.equal(evaluate([ok('a')], 'high', ['semgrep']).verdict, 'INCOMPLETE');
  assert.equal(evaluate([ok('a', [f('high')]), { tool: 'b', status: 'ERROR', findings: [] }], 'high').verdict, 'FAIL');
  assert.equal(evaluate([ok('a', [f('medium')])], 'medium').exitCode, 1);
});

t('trivy: vulnerabilities + misconfigurations, empty results', () => {
  const j = { Results: [{ Target: 'web.deps.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-1', PkgName: 'Foo', InstalledVersion: '1.0', FixedVersion: '1.1, 2.0', Severity: 'HIGH', Title: 'bad' }] },
    { Target: 'Dockerfile', Misconfigurations: [{ ID: 'DS002', Title: 'root user', Severity: 'MEDIUM', CauseMetadata: { StartLine: 3 } }] }] };
  const f = parseTrivy(JSON.stringify(j), 'repo');
  assert.equal(f.length, 2); assert.equal(f[0].severity, 'high'); assert.equal(f[0].fixed, '1.1'); assert.equal(f[1].location, 'repo: Dockerfile:3'); assert.ok(f[1].title.includes('misconfiguration'));
  assert.deepEqual(parseTrivy('{"SchemaVersion":2}', 'x'), []); assert.equal(parseTrivy('nope', 'x'), null);
});

t('zap: risk codes mapped, informational skipped', () => {
  const j = { site: [{ '@name': 'http://localhost:8080', alerts: [
    { pluginid: '10202', alert: 'Missing Anti-CSRF Tokens', riskcode: '2', instances: [{ uri: 'http://localhost:8080/a' }, { uri: 'http://localhost:8080/b' }], solution: '<p>Use tokens</p>' },
    { pluginid: '10096', alert: 'Timestamp Disclosure', riskcode: '1', instances: [] }, { pluginid: '1', alert: 'Info', riskcode: '0', instances: [] }] }] };
  const f = parseZap(JSON.stringify(j));
  assert.equal(f.length, 2); assert.equal(f[0].severity, 'medium'); assert.equal(f[0].id, 'ZAP-10202'); assert.ok(f[0].location.includes('+1 more')); assert.equal(f[0].solution, 'Use tokens'); assert.equal(f[1].severity, 'low');
});

t('DAST target safety: local only unless the host is named', () => {
  assert.equal(checkDastTarget('http://localhost:5000/x').ok, true);
  assert.equal(checkDastTarget('http://localhost:5000/x').containerUrl, 'http://host.docker.internal:5000/x');
  assert.equal(checkDastTarget('https://app.test').ok, true);
  const bad = checkDastTarget('https://example.com'); assert.equal(bad.ok, false); assert.ok(bad.reason.includes('--dast-allow-host'));
  assert.equal(checkDastTarget('https://example.com', ['example.com']).ok, true);
  assert.equal(checkDastTarget('ftp://localhost').ok, false); assert.equal(checkDastTarget('not a url').ok, false);
});

t('docker runtime choice: pull by default, --no-pull refuses, down engine reported', () => {
  assert.equal(chooseRuntime({ dockerUp: true, imageLocal: true, noPull: false }), 'docker');
  assert.equal(chooseRuntime({ dockerUp: true, imageLocal: false, noPull: false }), 'docker');
  assert.equal(chooseRuntime({ dockerUp: true, imageLocal: false, noPull: true }), 'pull-needed');
  assert.equal(chooseRuntime({ dockerUp: true, imageLocal: true, noPull: true }), 'docker');
  assert.equal(chooseRuntime({ dockerUp: false, imageLocal: false, noPull: false }), 'docker-down');
});

t('tool selection: groups like the team scan.ps1, zap only with a target', () => {
  assert.deepEqual(selectTools({ tool: ['all'] }), ['gitleaks', 'nuget', 'semgrep', 'osv', 'grype', 'trivy']);
  assert.deepEqual(selectTools({ tool: ['sca'] }), ['nuget', 'osv']);
  assert.deepEqual(selectTools({ tool: ['sast'] }), ['semgrep']);
  assert.deepEqual(selectTools({ tool: ['secrets'] }), ['gitleaks']);
  assert.deepEqual(selectTools({ tool: ['container'] }), ['grype', 'trivy']);
  assert.deepEqual(selectTools({ tool: ['all'], dast: true }), ['gitleaks', 'nuget', 'semgrep', 'osv', 'grype', 'trivy', 'zap']);
  assert.deepEqual(selectTools({ tool: ['all'], skip: ['semgrep'] }), ['gitleaks', 'nuget', 'osv', 'grype', 'trivy']);
  assert.deepEqual(selectTools({ tool: ['all'], only: ['trivy', 'osv'] }), ['osv', 'trivy']);
});

console.log(`\n${n} checks passed`);
