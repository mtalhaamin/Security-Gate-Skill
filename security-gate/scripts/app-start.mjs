// Starts the project's own web app on a free local port so the DAST scan (OWASP ZAP) has something to scan,
// and stops it again afterwards. Used by gate.mjs for --dast-auto and --dast-start.
// Plain Node, no dependencies. The app is always started on localhost.
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

const SKIP_DIRS = new Set(['node_modules', 'bin', 'obj', 'dist', 'build', 'target', 'vendor', 'packages', '.venv', 'venv', '__pycache__']);
const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };

// Finds files by name (and optional test) up to a depth, skipping dependency / build / dot folders.
function findFiles(root, match, maxDepth = 3) {
  const out = [];
  const walk = (dir, depth) => {
    let entries = []; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (e.isDirectory()) { if (depth < maxDepth && !e.name.startsWith('.') && !SKIP_DIRS.has(e.name)) walk(path.join(dir, e.name), depth + 1); }
      else if (match(e.name)) out.push(path.join(dir, e.name));
    }
  };
  walk(root, 0);
  return out;
}

// Works out how to start the project's web app. Returns { kind, cmd, cwd, label, problems[] } or null.
// The command contains {port}. Supported: ASP.NET Core, Node.js (Next.js, Vite, anything that reads PORT) and Django.
export function detectApp(root) {
  const rel = (p) => path.relative(root, p).split(path.sep).join('/') || '.';

  const webProjects = findFiles(root, (n) => /\.csproj$/i.test(n)).filter((p) => /Sdk="Microsoft\.NET\.Sdk\.Web"/i.test(read(p)));
  if (webProjects.length) {
    // Prefer a project that is not a test project and has a Program.cs next to it.
    const ranked = [...webProjects].sort((a, b) => score(a) - score(b));
    function score(p) { return (/test/i.test(p) ? 10 : 0) + (fs.existsSync(path.join(path.dirname(p), 'Program.cs')) ? 0 : 1); }
    const p = ranked[0];
    return { kind: 'dotnet', cwd: root, cmd: `dotnet run --project "${rel(p)}" --urls http://localhost:{port}`, label: `ASP.NET Core project ${rel(p)}`,
      problems: [], others: webProjects.length - 1 };
  }

  const pkgs = findFiles(root, (n) => n === 'package.json', 2).filter((p) => { const j = parseJson(read(p)); return j && j.scripts && (j.scripts.dev || j.scripts.start); });
  if (pkgs.length) {
    const p = pkgs[0]; const dir = path.dirname(p); const j = parseJson(read(p));
    const deps = { ...(j.dependencies || {}), ...(j.devDependencies || {}) };
    const script = j.scripts.dev ? 'dev' : 'start';
    let extra = '';
    if (deps.next) extra = ' -- -p {port}';
    else if (deps.vite) extra = ' -- --port {port} --strictPort';
    const problems = fs.existsSync(path.join(dir, 'node_modules')) ? [] : [`dependencies are not installed in ${rel(dir)}; run "npm install" there first`];
    return { kind: 'node', cwd: dir, cmd: `npm run ${script}${extra}`, label: `Node.js project ${rel(dir)} (npm run ${script})`, problems, others: pkgs.length - 1 };
  }

  const manage = findFiles(root, (n) => n === 'manage.py', 2)[0];
  if (manage) return { kind: 'django', cwd: path.dirname(manage), cmd: 'python manage.py runserver {port} --noreload', label: `Django project ${rel(path.dirname(manage))}`, problems: [], others: 0 };

  return null;
}
function parseJson(t) { try { return JSON.parse(t.replace(/^﻿/, '')); } catch { return null; } }

export function freePort() {
  const r = spawnSync(process.execPath, ['-e', "const s=require('net').createServer();s.listen(0,'127.0.0.1',()=>{console.log(s.address().port);s.close()})"], { encoding: 'utf8', timeout: 15000 });
  const n = parseInt(String(r.stdout).trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
// True while the process is running. On Linux/macOS a finished child stays a "zombie" until Node reaps it, and Node cannot
// do that while this script waits, so process.kill(pid, 0) would still say "alive"; ps shows the real state (Z = finished).
function alive(pid) {
  if (process.platform === 'win32') { try { process.kill(pid, 0); return true; } catch { return false; } }
  const r = spawnSync('ps', ['-o', 'stat=', '-p', String(pid)], { encoding: 'utf8', timeout: 10000 });
  const st = String(r.stdout || '').trim();
  return !!st && !st.startsWith('Z');
}
function httpAnswers(url) { // any HTTP answer (even 404 or 500) means the server is up
  const r = spawnSync(process.execPath, ['-e', `fetch(${JSON.stringify(url)},{signal:AbortSignal.timeout(5000),redirect:'manual'}).then(()=>process.exit(0),()=>process.exit(1))`], { timeout: 15000 });
  return r.status === 0;
}

// Starts the app and waits until it answers. Returns { ok, url, pid, log, note }.
export function startApp({ command, cwd, port, logFile, timeoutMs = 4 * 60 * 1000, env = {} }) {
  const cmd = command.replace(/\{port\}/g, String(port));
  const url = `http://localhost:${port}`;
  const fd = fs.openSync(logFile, 'w');
  const win = process.platform === 'win32';
  const child = spawn(cmd, { cwd, shell: true, detached: !win, windowsHide: true, stdio: ['ignore', fd, fd], env: { ...process.env, PORT: String(port), ...env } });
  child.on('error', () => { /* reported through the log and the wait loop */ });
  fs.closeSync(fd); // the child keeps its own copy; closing ours lets the log file be deleted on Windows
  const handle = { pid: child.pid, url, log: logFile, cmd };
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (!alive(child.pid)) { stopApp(handle); return { ...handle, ok: false, note: `the app exited before it answered (see ${logFile}): ${tailOf(logFile)}` }; }
    if (httpAnswers(url)) return { ...handle, ok: true, note: `started "${cmd}" on ${url}` };
    sleep(2000);
  }
  stopApp(handle);
  return { ...handle, ok: false, note: `the app did not answer on ${url} within ${Math.round(timeoutMs / 1000)} s (see ${logFile}): ${tailOf(logFile)}` };
}
function tailOf(file) { return read(file).trim().split(/\r?\n/).slice(-3).join(' | ').slice(0, 300); }

// Stops the app and everything it started.
export function stopApp(h) {
  if (!h || !h.pid) return;
  if (process.platform === 'win32') spawnSync('taskkill', ['/PID', String(h.pid), '/T', '/F'], { stdio: 'ignore' });
  else { try { process.kill(-h.pid, 'SIGTERM'); } catch { try { process.kill(h.pid, 'SIGTERM'); } catch { /* already gone */ } } }
}
