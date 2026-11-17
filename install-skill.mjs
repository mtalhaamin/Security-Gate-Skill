#!/usr/bin/env node
// Copies the security-gate skill into the folder each coding agent loads skills from.
// Node >= 20, no dependencies.
//   node install-skill.mjs --agent claude|cursor|codex|antigravity|all [--project <dir> | --global] [--agents-md] [--force] [--dry-run]
//
// Folders (Agent Skills layout: <folder>/security-gate/SKILL.md):
//   agent        project folder          global folder
//   claude       .claude/skills          ~/.claude/skills
//   cursor       .cursor/skills          ~/.cursor/skills
//   codex        .agents/skills          ~/.agents/skills
//   antigravity  .agents/skills          ~/.gemini/antigravity/skills
// "all" = claude + codex + antigravity (Cursor also reads .claude/skills and .agents/skills, so it needs no extra copy).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, 'security-gate');
const PROJECT = { claude: ['.claude', 'skills'], cursor: ['.cursor', 'skills'], codex: ['.agents', 'skills'], antigravity: ['.agents', 'skills'] };
const GLOBAL = { claude: ['.claude', 'skills'], cursor: ['.cursor', 'skills'], codex: ['.agents', 'skills'], antigravity: ['.gemini', 'antigravity', 'skills'] };
const MARK_START = '<!-- security-gate:start -->'; const MARK_END = '<!-- security-gate:end -->';

function parse(argv) {
  const o = { agents: [], project: process.cwd(), global: false, agentsMd: false, force: false, dry: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--agent') o.agents = String(argv[++i] || '').split(',').filter(Boolean);
    else if (a === '--project') o.project = path.resolve(argv[++i] || '');
    else if (a === '--global') o.global = true; else if (a === '--agents-md') o.agentsMd = true;
    else if (a === '--force') o.force = true; else if (a === '--dry-run') o.dry = true;
    else if (a === '-h' || a === '--help') o.help = true; else throw new Error(`unknown argument ${a}`);
  }
  if (o.agents.includes('all')) o.agents = [...new Set([...o.agents.filter((a) => a !== 'all'), 'claude', 'codex', 'antigravity'])];
  for (const a of o.agents) if (!PROJECT[a]) throw new Error(`unknown agent "${a}" (claude, cursor, codex, antigravity, all)`);
  return o;
}

function agentsMdBlock(rel) {
  return `${MARK_START}
## Security gate

When asked to run the security gate, scan this repository for secrets or vulnerabilities, or check it is clean before a commit, PR or release, use the \`security-gate\` skill at \`${rel}/security-gate/SKILL.md\` (follow it exactly). In short:

1. Tell the user once that the first run pulls official Docker images (about 0.6 GB, plus 1.1 GB for ZAP if DAST is used) and wait for their yes. Needs Docker Desktop and Node.js 20+; the .NET SDK only for .NET projects.
2. \`node ${rel}/security-gate/scripts/gate.mjs --root .\` runs OSV-Scanner + NuGet Audit, Semgrep, gitleaks, Trivy + Grype (for OWASP ZAP add \`--dast-auto\` to let the gate start, scan and stop the app, or \`--dast-url http://localhost:PORT\` for an app that is already running; local targets only; ask the user first, because \`--dast-auto\` runs the project's code) and writes \`.work/security-gate/security-report.pdf\` (findings ranked L0 High, L1 Medium, L2 Low).
3. Exit code 0 = PASS, 1 = FAIL, 2 = INCOMPLETE. Never call the repo clean unless the verdict is PASS. Never print secret values.
${MARK_END}
`;
}

function main() {
  const o = parse(process.argv.slice(2));
  if (o.help || !o.agents.length) {
    console.log('usage: node install-skill.mjs --agent claude|cursor|codex|antigravity|all [--project <dir> | --global] [--agents-md] [--force] [--dry-run]');
    return o.help ? 0 : 2;
  }
  if (!fs.existsSync(path.join(SRC, 'SKILL.md'))) { console.error(`skill source not found: ${SRC}`); return 2; }
  const base = o.global ? os.homedir() : o.project;
  if (!o.global && !fs.existsSync(base)) { console.error(`project folder not found: ${base}`); return 2; }
  const map = o.global ? GLOBAL : PROJECT;
  const dests = [...new Set(o.agents.map((a) => path.join(base, ...map[a])))];
  for (const root of dests) {
    const dest = path.join(root, 'security-gate');
    if (fs.existsSync(dest) && !o.force) { console.log(`skip   ${dest} (exists; use --force to replace)`); continue; }
    console.log(`${o.dry ? 'would copy' : 'copy  '} -> ${dest}`);
    if (o.dry) continue;
    if (fs.existsSync(dest)) fs.rmSync(dest, { recursive: true, force: true });
    fs.mkdirSync(root, { recursive: true });
    fs.cpSync(SRC, dest, { recursive: true });
  }
  if (o.agentsMd && !o.global) {
    const first = dests.find((d) => d.includes(`${path.sep}.agents${path.sep}`)) || dests[0];
    const rel = path.relative(base, first).split(path.sep).join('/');
    const f = path.join(base, 'AGENTS.md'); const block = agentsMdBlock(rel);
    let t = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : '';
    const s = t.indexOf(MARK_START); const e = t.indexOf(MARK_END);
    t = s >= 0 && e > s ? t.slice(0, s) + block.trimEnd() + t.slice(e + MARK_END.length) : (t ? t.trimEnd() + '\n\n' : '') + block;
    console.log(`${o.dry ? 'would update' : 'update'} ${f}`);
    if (!o.dry) fs.writeFileSync(f, t);
  }
  console.log('Needs Docker Desktop and Node.js 20+ (the .NET SDK only for .NET projects). The first gate run pulls the official scanner images (sizes are printed).');
  console.log('Restart the agent so it picks up the new skill.');
  return 0;
}
try { process.exit(main()); } catch (e) { console.error(`error: ${e.message}`); process.exit(2); }
