# Security Gate Skill

One command, one verdict: runs **gitleaks**, **NuGet Audit**, **semgrep**, **osv-scanner** and **grype** over a
codebase and returns `PASS`, `FAIL` or `INCOMPLETE`, plus a PDF report that ranks every finding as
**L0 High / L1 Medium / L2 Low** with the action to take.

It is an [Agent Skills](https://agentskills.io) package (`SKILL.md`), so it works in **Claude Code, Cursor, Codex and
Antigravity**. The runner itself is a plain Node script, so any agent (or CI job) that can run a shell command can use it.

![Example report](docs/example-report.png)

Example PDF: [docs/example-report.pdf](docs/example-report.pdf) (synthetic data, not a real project).

---

## Contents

1. [What it checks](#what-it-checks)
2. [Quick start](#quick-start)
3. [Use it in your coding agent](#use-it-in-your-coding-agent)
4. [How a run works](#how-a-run-works)
5. [Verdicts, exit codes and priorities](#verdicts-exit-codes-and-priorities)
6. [Output files](#output-files)
7. [Options](#options)
8. [Suppressing accepted risks](#suppressing-accepted-risks)
9. [Known issues and troubleshooting](#known-issues-and-troubleshooting)
10. [Safety rules](#safety-rules)
11. [Repository layout](#repository-layout)
12. [Limits and status](#limits-and-status)

---

## What it checks

| Tool | Looks for | Needs |
|---|---|---|
| **gitleaks** | Hard-coded secrets: working tree and git history | `gitleaks` |
| **NuGet Audit** | Known-vulnerable NuGet packages, direct and transitive (`dotnet list package --vulnerable`) | .NET SDK 8+ |
| **semgrep** | Insecure code patterns (SAST): security-audit, OWASP Top 10, C#, secrets rule packs | `semgrep`, network for rule packs |
| **osv-scanner** | Known CVEs in dependencies (npm, NuGet via `deps.json`, pip, Go, ...) | `osv-scanner` |
| **grype** | Known CVEs in dependencies and the .NET runtime files in a publish output | `grype`, network for its database on first run |

## Quick start

Windows is the primary platform (PowerShell installer). Needs Node 20+; semgrep needs Python 3.

```powershell
git clone <this-repo-url> Security-Gate-Skill
cd Security-Gate-Skill

# 1. Install the scanners into ./tools (nothing is installed system-wide, downloads are SHA256-verified)
powershell -ExecutionPolicy Bypass -File .\install-tools.ps1

# 2. Check everything is found
node security-gate/scripts/gate.mjs --preflight

# 3. Scan a project
node security-gate/scripts/gate.mjs --root C:\path\to\your-project
```

Reports land in `<project>\.work\security-gate\`. Exit code: `0` PASS, `1` FAIL, `2` INCOMPLETE.

Linux / macOS: install `gitleaks`, `osv-scanner`, `grype` (package manager or release binaries) and `pip install semgrep`
so they are on `PATH`; `gate.mjs` finds them there. (Not tested on Linux/macOS yet.)

## Use it in your coding agent

Install the skill into a project (or globally) with one command:

```bash
node install-skill.mjs --agent all --project /path/to/project --agents-md
```

| Agent | Project folder | Global folder (`--global`) | Flag |
|---|---|---|---|
| Claude Code | `.claude/skills/security-gate` | `~/.claude/skills` | `--agent claude` |
| Cursor | `.cursor/skills/security-gate` (also reads `.claude/skills` and `.agents/skills`) | `~/.cursor/skills` | `--agent cursor` |
| Codex | `.agents/skills/security-gate` | `~/.agents/skills` | `--agent codex` |
| Antigravity | `.agents/skills/security-gate` (legacy `.agent/skills` still read) | `~/.gemini/antigravity/skills` | `--agent antigravity` |

- `--agent all` = Claude Code + Codex + Antigravity (two folders: `.claude/skills` and `.agents/skills`; Cursor reads both).
  Add `cursor` explicitly to also create `.cursor/skills`: `--agent all,cursor`.
- `--agents-md` adds a short, idempotent "Security gate" block to the project's `AGENTS.md`, for agents or versions
  without skill support (Codex, Cursor and Antigravity read `AGENTS.md`).
- `--force` replaces an existing copy; `--dry-run` shows what would happen. Restart the agent afterwards.
- The installer writes `tools.path` next to the skill so the copy finds the scanners installed in this repo's `tools/`.
  Override with the `SECURITY_GATE_TOOLS` environment variable.

Then just ask your agent: **"run the security gate"**. It will run the preflight, run the gate, read the report and
summarise it. The skill tells the agent never to install tools without your yes and never to print secrets.

> The folder locations above come from each product's documentation. The skill was run end to end in Claude Code;
> loading it inside Cursor, Codex and Antigravity has not been tested here.

## How a run works

1. **Preflight**: finds each tool (`tools/` first, then `PATH`). A missing tool becomes `NOT-RUN`, never a silent pass.
2. **Publish (only for .NET)**: web/exe projects are published to a temp folder outside the repo so osv-scanner and grype
   can read `*.deps.json` (they do not read `.csproj`). The folder is deleted afterwards.
3. **Scan**: gitleaks, NuGet audit, semgrep, osv-scanner, grype run in turn. Tool output is parsed into one finding list.
4. **Suppressions** (`.security-gate/ignore.json`) are applied; only valid, unexpired entries count.
5. **Verdict + reports**: a finding at or above `--fail-on` (default `high`) is blocking.

## Verdicts, exit codes and priorities

| Verdict | Exit | Meaning |
|---|---|---|
| **PASS** | 0 | Every selected tool ran and nothing blocking was found |
| **FAIL** | 1 | At least one blocking finding |
| **INCOMPLETE** | 2 | A tool is missing, errored, had nothing to scan (`NO-COVERAGE`) or was skipped. Not a pass |

| Priority | Severity it covers | What to do |
|---|---|---|
| **L0 High** | Critical, High | Fix now. Any secret leak is L0: rotate the credential first |
| **L1 Medium** | Medium, and "unknown" severity | Fix in the current sprint |
| **L2 Low** | Low, Negligible | Track, fix when convenient |

## Output files

Written to `<project>\.work\security-gate\`:

| File | Content |
|---|---|
| `security-report.pdf` | Key points, per-tool table, findings grouped L0 / L1 / L2 with the action for each |
| `report.md`, `report.json` | Same data as text / machine-readable |
| `gitleaks-*.json`, `osv-*.json`, `grype-*.json`, `semgrep.json`, `nuget-*.json` | Raw tool output |

The PDF is printed by the Edge or Chrome already on the machine (no extra install). If none is found you get an HTML file
to print yourself. Rebuild it any time: `node security-gate/scripts/report-pdf.mjs <report.json> [out.pdf]`.

## Options

```text
node security-gate/scripts/gate.mjs [options]
  --root <dir>            project to scan (default: current folder)
  --out <dir>             report folder (default: <root>/.work/security-gate)
  --fail-on <level>       critical | high | medium | low   (default: high)
  --only a,b / --skip a   tools: gitleaks, nuget, semgrep, osv, grype  (skipping makes the gate INCOMPLETE)
  --preflight             only check the tools, scan nothing, write nothing
  --no-publish            do not publish .NET projects (osv/grype then rely on lock files)
  --no-history            skip the gitleaks git-history scan
  --no-pdf                skip the PDF
  --semgrep-config <cfg>  extra/other semgrep rule packs (repeatable), e.g. p/javascript
  --exclude <glob>        extra semgrep exclude (repeatable)
  --ignore <file>         suppressions file (default: <root>/.security-gate/ignore.json)
  --keep                  keep the temp publish folder
```

## Suppressing accepted risks

`<project>/.security-gate/ignore.json` (template: [`security-gate/references/ignore.example.json`](security-gate/references/ignore.example.json)).
Each entry needs `id`, a real `reason` and an `expires` date. Entries without these, or expired ones, are ignored and
listed in the report so the finding counts again. Suppressed findings stay visible in the report.

## Known issues and troubleshooting

Real problems found while testing on an Umbraco (.NET) project, and what to do:

- **gitleaks reports hundreds of `generic-api-key` hits in `uSync/**/*.config`.**
  Those lines hold Umbraco content GUIDs (`Key="..."`), not secrets (336 of 344 flagged lines contained only GUIDs; the
  other 8 were short lines of 70-110 characters that were not individually inspected). Suppress by `id` + `path`
  (`uSync/`) with a reason and expiry. The gate does **not** hide them by default.
- **osv-scanner flags NuGet packages with a 4-part version `x.y.z.0` (for example `10.0.0.0`).**
  That is the assembly version read from `deps.json`, not the package version, so it matches old advisories. The gate
  labels these "probable false positive"; confirm the real version with NuGet audit
  (`dotnet list package --include-transitive`), then suppress.
- **osv-scanner and grype found nothing for .NET at first.** They read `deps.json` / `packages.lock.json`, not `.csproj`.
  Fixed by the publish step. Alternative: enable `RestorePackagesWithLockFile` and commit `packages.lock.json`.
- **grype flags `Microsoft.AspNetCore.*` / `System.*` 10.0.13 files from `refs/`.**
  These are the installed .NET SDK / targeting-pack patch level, a real finding about the machine. Update the .NET SDK /
  runtime to the fixed patch.
- **Tooling folders were scanned.** osv-scanner initially scanned `.claude/**` lockfiles (about 94 npm findings of
  tooling, not product code). It now scans each top-level project folder and skips dot-folders, matching semgrep and grype.
- **gitleaks history scan says "repository has no commits yet".** Expected before the first commit; only the working tree
  is scanned (and the report says so).
- **The first grype run is slow and large.** It downloads its vulnerability database into `tools/grype-db`
  (about 3 GB seen here). Keep `tools/` out of git (already in `.gitignore`).
- **semgrep needs Python 3 and network.** It runs in its own venv (`tools/semgrep-venv`); it worked natively on Windows
  (semgrep 1.185.0). If it fails the gate reports `ERROR` for semgrep, not PASS.
- **No PDF produced.** Needs Edge or Chrome (`PDF_BROWSER` env var can point to a browser). The HTML is kept as fallback.
- **`INCOMPLETE` although nothing was found.** A tool was missing, skipped, or had nothing to scan. Run `--preflight`.
- **A tool's output format changes.** The gate then reports `ERROR` for that tool instead of passing. Tested versions:
  gitleaks 8.30.1, osv-scanner 2.7.1, grype 0.122.0, semgrep 1.185.0, .NET SDK 10.0.402.

## Safety rules

- The runner installs nothing. `install-tools.ps1` is the only installer, runs only when you run it, and verifies SHA256
  checksums (taken from the same release page; the grype sigstore signature is not verified).
- Secret values are never copied: gitleaks runs with `--redact`, semgrep findings are cut down to rule + location.
  Secret-bearing files (`appsettings.Development.json`, `.env*`, `*.pfx`, ...) are excluded from semgrep.
- The scan makes network calls (nuget.org, semgrep registry, grype DB) and runs `dotnet restore` / `dotnet publish`
  on the scanned project.

## Repository layout

```
Security-Gate-Skill/
  README.md
  install-tools.ps1            downloads + verifies the scanners into ./tools (Windows)
  install-skill.mjs            copies the skill into Claude Code / Cursor / Codex / Antigravity folders
  docs/                        example report (png + pdf)
  security-gate/               <- the skill (Agent Skills format)
    SKILL.md                   instructions the agent follows
    scripts/gate.mjs           runner (Node 20+, no npm dependencies)
    scripts/report-pdf.mjs     PDF builder
    scripts/gate.selftest.mjs  offline self-test (node security-gate/scripts/gate.selftest.mjs)
    references/                tool details, ignore.json template
  tools/                       (git-ignored) installed scanners
```

## Limits and status

- Scanners find **known** issues only. A PASS is not a penetration test.
- No reachability analysis: a blocking CVE in an unused code path still needs a reasoned suppression.
- osv-scanner and grype use different databases and can disagree; each is reported separately.
- Tested end to end on one Umbraco/.NET project on Windows. The offline self-test (9 checks) covers parsers, suppressions
  and verdict logic.
- License: [MIT](LICENSE). The scanners it installs (gitleaks, osv-scanner, grype, semgrep) have their own licenses.
