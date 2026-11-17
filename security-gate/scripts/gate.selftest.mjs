// Offline self-test for gate.mjs parsers and verdict logic. No scanner needed.
// Run: node .claude/skills/security-gate/scripts/gate.selftest.mjs
// NOTE: fixtures follow the documented output of each tool. They prove the gate logic, not that a
// given scanner version still prints exactly this shape; the first real run of each tool confirms that.
import assert from 'node:assert/strict';
import { parseGitleaks, parseDotnetList, parseSemgrep, parseOsv, parseGrype, applyIgnores, evaluate, extractJson, cvssToSeverity } from './gate.mjs';

let n = 0; const t = (name, fn) => { fn(); n++; console.log('ok  ' + name); };

t('extractJson skips a banner before JSON', () => assert.deepEqual(extractJson('warn: x\n{"a":1}'), { a: 1 }));
t('cvss mapping', () => { assert.equal(cvssToSeverity('9.8'), 'critical'); assert.equal(cvssToSeverity('7.5'), 'high'); assert.equal(cvssToSeverity('5'), 'medium'); assert.equal(cvssToSeverity('2'), 'low'); assert.equal(cvssToSeverity(''), null); });

t('gitleaks: never copies the secret', () => {
  const f = parseGitleaks(JSON.stringify([{ RuleID: 'generic-api-key', Description: 'key', File: 'a/b.cs', StartLine: 7, Secret: 'REDACTED', Match: 'REDACTED', Commit: 'abcdef123456', Fingerprint: 'fp1' }]));
  assert.equal(f.length, 1); assert.equal(f[0].severity, 'critical'); assert.equal(f[0].location, 'a/b.cs:7 @abcdef12');
  assert.ok(!JSON.stringify(f).includes('REDACTED'));
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

console.log(`\n${n} checks passed`);
