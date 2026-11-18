// Offline self-test for gate.mjs parsers and verdict logic. No scanner needed.
// Run: node .claude/skills/security-gate/scripts/gate.selftest.mjs
// NOTE: fixtures follow the documented output of each tool. They prove the gate logic, not that a
// given scanner version still prints exactly this shape; the first real run of each tool confirms that.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectApp, startApp, freePort } from './app-start.mjs';
import { securityScore, buildHtml, owaspCategory } from './report-pdf.mjs';
import { cweList, semgrepCoverage, redactRaw, packageMatches, pathMatches } from './gate.mjs';
import { parseIgnoredList, trivySkipArgs, looksLikeGuidOnly, semgrepRulesets, detectLanguages, parseGitleaks, parseDotnetList, parseSemgrep, parseOsv, parseGrype, parseTrivy, parseZap, checkDastTarget, chooseRuntime, selectTools, applyIgnores, evaluate, extractJson, cvssToSeverity } from './gate.mjs';

let n = 0; const t = (name, fn) => { fn(); n++; console.log('ok  ' + name); };

t('semgrep: scan errors are never a PASS (issue #1)', () => {
  const ok = semgrepCoverage({ errors: [], paths: { scanned: ['a.cs', 'b.cs'] } }, []);
  assert.equal(ok.status, 'OK');
  assert.equal(semgrepCoverage({ errors: Array.from({ length: 5 }, (_, i) => ({ level: 'warn', path: `f${i}.cs` })), paths: { scanned: ['f0.cs', 'f1.cs', 'f2.cs', 'f3.cs', 'f4.cs'] } }, []).status, 'ERROR'); // nothing parsed
  assert.equal(semgrepCoverage({ errors: [{ level: 'error', type: 'Rule parse error' }], paths: { scanned: ['a.cs'] } }, []).status, 'ERROR'); // rules did not load
  assert.equal(semgrepCoverage({ errors: [{ level: 'error', type: 'Rule parse error' }], paths: { scanned: ['a.cs'] } }, [{ id: 'x' }]).status, 'PARTIAL');
  assert.equal(semgrepCoverage({ errors: [], paths: { scanned: [] } }, []).status, 'ERROR'); // no files scanned
  const many = Array.from({ length: 50 }, (_, i) => `f${i}.cs`);
  assert.equal(semgrepCoverage({ errors: [{ level: 'warn', path: 'f1.cs' }], paths: { scanned: many } }, []).status, 'OK'); // one bad file of 50 is noted, not fatal
  // Partly parsed files still count as scanned, so the result is OK (real case: 28 of 111 C# files)
  const part = Array.from({ length: 28 }, (_, i) => ({ level: 'warn', type: ['PartialParsing', [{ path: `p${i}.cs` }]], path: `p${i}.cs` }));
  const pc = semgrepCoverage({ errors: part, paths: { scanned: Array.from({ length: 111 }, (_, i) => `p${i}.cs`) } }, []);
  assert.equal(pc.status, 'OK'); assert.match(pc.note, /28 parsed partially/);
  assert.equal(semgrepCoverage({ errors: [...part, { level: 'error', type: 'Rule parse error' }], paths: { scanned: ['a.cs'] } }, []).status, 'ERROR'); // a real rule error still counts
  const res = (status, findings) => ({ tool: 'semgrep', status, findings });
  assert.equal(evaluate([res('ERROR', [])], 'high').verdict, 'INCOMPLETE');
  assert.equal(evaluate([res('PARTIAL', [{ severity: 'low' }])], 'high').verdict, 'INCOMPLETE');
  assert.equal(evaluate([res('PARTIAL', [{ severity: 'high' }])], 'high').verdict, 'FAIL'); // what it did find still blocks
});

t('raw tool outputs lose secret text and matched lines before they are kept (issue #1)', () => {
  const tv = redactRaw('trivy', { Results: [{ Secrets: [{ RuleID: 'aws', Match: 'AKIAREALKEY', Code: { Lines: [{ Content: 'key=AKIAREALKEY' }] } }] }] });
  assert.ok(!JSON.stringify(tv).includes('AKIAREALKEY')); assert.equal(tv.Results[0].Secrets[0].RuleID, 'aws');
  const sg = redactRaw('semgrep', { results: [{ check_id: 'r', extra: { lines: 'pwd="hunter2"', metavars: { $X: { abstract_content: 'hunter2' } }, message: 'm' } }] });
  assert.ok(!JSON.stringify(sg).includes('hunter2')); assert.equal(sg.results[0].extra.message, 'm');
  const zp = redactRaw('zap', { site: [{ alerts: [{ alert: 'a', instances: [{ uri: 'http://x/', evidence: 'token=abc123', otherinfo: 'abc123' }] }] }] });
  assert.ok(!JSON.stringify(zp).includes('abc123')); assert.equal(zp.site[0].alerts[0].instances[0].uri, 'http://x/');
});

t('suppressions match exactly, not by substring (issue #1)', () => {
  assert.ok(packageMatches('foo', 'foo@1.0.0')); assert.ok(packageMatches('foo@1.0.0', 'foo@1.0.0')); assert.ok(!packageMatches('foo', 'foobar@1.0.0'));
  assert.ok(packageMatches('@scope/pkg', '@scope/pkg@2.0.0')); assert.ok(!packageMatches('foo@1.0.0', 'foo@1.0.1'));
  assert.ok(pathMatches('src/a.cs', 'src/a.cs:12')); assert.ok(pathMatches('src/a.cs:12', 'src/a.cs:12')); assert.ok(!pathMatches('src/a', 'src/abc/x.cs:3'));
  assert.ok(pathMatches('uSync/', 'uSync/v17/a.config:2')); assert.ok(!pathMatches('uSync', 'uSync/v17/a.config:2'));
  assert.ok(pathMatches('Web.deps.json', 'published:Web: Web.deps.json')); // a "label: " prefix is ignored
  const r = applyIgnores([{ tool: 'osv', id: 'CVE-1', package: 'foobar@1.0.0', location: 'x' }], [{ id: 'CVE-1', package: 'foo', reason: 'not used here', expires: '2999-01-01' }]);
  assert.equal(r.active.length, 1); assert.equal(r.suppressed.length, 0);
});

t('owasp: findings land in the official OWASP Top 10:2025 category', () => {
  assert.deepEqual(cweList('CWE-89: Improper Neutralization'), [89]); assert.deepEqual(cweList(['CWE-79', 'CWE-79', '693']), [79, 693]); assert.deepEqual(cweList('-1'), []);
  assert.equal(owaspCategory({ tool: 'semgrep', cwe: [89] }), 'A05');                         // SQL injection
  assert.equal(owaspCategory({ tool: 'semgrep', owasp: ['A01:2021'], cwe: [89] }), 'A01');    // the rule's own OWASP tag wins (2021 A01 -> 2025 A01)
  assert.equal(owaspCategory({ tool: 'semgrep', owasp: ['A03:2021'] }), 'A05');               // 2021 Injection -> 2025 A05
  assert.equal(owaspCategory({ tool: 'semgrep', owasp: ['A03:2021', 'A05:2025'] }), 'A05');   // a 2025 tag is used as is
  assert.equal(owaspCategory({ tool: 'gitleaks', id: 'aws-access-token' }), 'A07');          // hard-coded credentials, CWE-798
  assert.equal(owaspCategory({ tool: 'osv', id: 'CVE-1' }), 'A03');                            // vulnerable library = supply chain
  assert.equal(owaspCategory({ tool: 'trivy', title: '[misconfiguration] root user' }), 'A02');
  assert.equal(owaspCategory({ tool: 'zap', cwe: [22] }), 'A01');                              // path traversal
  assert.equal(owaspCategory({ tool: 'zap', cwe: [] }), null);
});

t('osv: NuGet assembly versions (x.y.z.0) are ranked Low and keep the reported severity', () => {
  const j = { results: [{ source: { path: '/pub/Web.deps.json' }, packages: [
    { package: { name: 'Microsoft.AspNetCore.DataProtection', version: '10.0.0.0', ecosystem: 'NuGet' }, vulnerabilities: [{ id: 'GHSA-9', aliases: ['CVE-2026-1'], summary: 'EoP' }], groups: [{ ids: ['GHSA-9', 'CVE-2026-1'], max_severity: '9.8' }] },
    { package: { name: 'Real.Pkg', version: '1.2.3', ecosystem: 'NuGet' }, vulnerabilities: [{ id: 'GHSA-8', summary: 'x' }], groups: [{ ids: ['GHSA-8'], max_severity: '7.5' }] }] }] };
  const [asm, real] = parseOsv(JSON.stringify(j), 'published:Web', '/pub/');
  assert.equal(asm.severity, 'low'); assert.equal(asm.reportedSeverity, 'critical'); assert.match(asm.title, /probable false positive, reported critical/);
  assert.equal(real.severity, 'high'); assert.equal(real.reportedSeverity, undefined);
});

t('score: grade by worst finding, points per distinct issue, capped when a check did not run', () => {
  const F = (id, severity) => ({ id, severity });
  const tool = (name, final, findings = []) => ({ tool: name, final, findings });
  const ex = { tools: [tool('gitleaks', 'FAIL', [F('k', 'critical')]), tool('semgrep', 'FAIL', [F('sqli', 'high'), F('cookie', 'low')]),
    tool('nuget', 'FAIL', [F('A', 'high'), F('B', 'medium'), F('B', 'medium')]), tool('osv', 'FAIL', [F('C', 'high')]),
    tool('trivy', 'PASS', [F('DS', 'medium')]), tool('zap', 'PASS', [F('Z1', 'medium'), F('Z2', 'low')]), tool('grype', 'PASS')] };
  const s = securityScore(ex);
  assert.equal(s.grade, 'E'); assert.equal(s.score, 34); assert.deepEqual(s.coverage, { ran: 7, total: 7 }); assert.equal(s.complete, true);
  assert.deepEqual(securityScore({ tools: [tool('gitleaks', 'PASS'), tool('nuget', 'N/A')] }), { grade: 'A', score: 100, coverage: { ran: 1, total: 1 }, complete: true, capped: false, issues: { critical: 0, high: 0, medium: 0, low: 0 } });
  const lows = securityScore({ tools: [tool('gitleaks', 'PASS', Array.from({ length: 336 }, () => F('guid-like', 'low')).concat([F('x', 'low')]))] });
  assert.equal(lows.grade, 'B'); assert.equal(lows.score, 98); // 336 hits of one rule are one issue
  const inc = securityScore({ tools: [tool('gitleaks', 'PASS'), tool('semgrep', 'NOT-RUN')], skipped: ['zap'] });
  assert.equal(inc.grade, 'C'); assert.equal(inc.capped, true); assert.deepEqual(inc.coverage, { ran: 1, total: 3 });
  const html = buildHtml({ generated: '2026-11-17T10:00:00Z', failOn: 'high', verdict: 'FAIL', tools: ex.tools.map((x) => ({ ...x, findings: x.findings.map((f) => ({ ...f, tool: x.tool, severityKnown: true, location: 'a.cs:1', package: '', title: f.id })) })) }, 'Demo');
  assert.ok(html.includes('class="grade"') && html.includes('>E</div>') && html.includes('<b>34</b>') && html.includes('7 of 7 checks ran'));
});

t('trivy: ignored paths are passed as container paths, which Trivy matches', () => {
  const a = trivySkipArgs({ dirs: ['src/App/umbraco'], files: ['src/App/appsettings.Development.json'] });
  assert.ok(a.join(' ').includes('--skip-files /src/src/App/appsettings.Development.json'));
  assert.ok(a.join(' ').includes('--skip-dirs /src/src/App/umbraco'));
  assert.ok(!a.includes('src/App/appsettings.Development.json') && !a.includes('src/App/umbraco'));   // the relative form is the bug
  assert.ok(a.includes('**/node_modules'));                                                            // the noise folders stay
});

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
    const a = detectApp(net); assert.equal(a.kind, 'dotnet'); assert.equal(a.cmd, 'dotnet run --project src/Site/Site.csproj --urls http://localhost:{port}'); assert.equal(a.others, 1);
    assert.equal(a.file, 'dotnet'); assert.equal(a.args[2], path.join(net, 'src', 'Site', 'Site.csproj')); assert.ok(!a.needsShell); // path is an argument, never shell text
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
    // A detected app runs without a shell: shell syntax in an argument (e.g. from a folder name) is passed as plain text.
    const evil = 'x" & echo INJECTED & "; touch pwned; #';
    const s = startApp({ file: process.execPath, args: ['-e', 'console.log("ARG=" + process.argv[1])', evil], cwd: d, port: freePort(), logFile: path.join(d, 'evil.log'), timeoutMs: 30000 });
    assert.equal(s.ok, false);
    const log = fs.readFileSync(path.join(d, 'evil.log'), 'utf8');
    assert.ok(log.includes('ARG=' + evil)); assert.ok(!/^INJECTED/m.test(log)); assert.ok(!fs.existsSync(path.join(d, 'pwned')));
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
