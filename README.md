# Security Gate Skill

One command, one verdict. Runs the whole scanner set through **official Docker images** and returns `PASS`, `FAIL` or `INCOMPLETE`,
plus a PDF report that ranks every finding **L0 High / L1 Medium / L2 Low** with the action to take.

| Category | Tool |
|---|---|
| SCA (dependencies) | **OSV-Scanner**, **NuGet Audit** |
| SAST (code) | **Semgrep** |
| Secrets | **gitleaks** (working tree + git history), Trivy secret scan |
| Containers / filesystem / IaC | **Trivy**, **Grype** (source tree, published .NET output, container images) |
| DAST (running app) | **OWASP ZAP** (local targets only) |

It is an [Agent Skills](https://agentskills.io) package (`SKILL.md`), so it works in **Claude Code, Cursor, Codex and Antigravity**. The runner
is a plain Node script, so any agent (or CI job) that can run a shell command can use it. The tool list and group names (`sca`, `sast`,
`secrets`, `container`, `dast`) follow the team's `scan.ps1`; this skill adds one verdict with exit codes, a prioritised PDF, suppressions
with expiry, pinned image versions and safety checks.

![Example report](docs/example-report.png)

Example PDF: [docs/example-report.pdf](docs/example-report.pdf) (synthetic data, not a real project).

---

## Contents

1. [Requirements](#requirements)
2. [Quick start](#quick-start)
3. [Use it in your coding agent](#use-it-in-your-coding-agent)
4. [Scan groups, images and DAST](#scan-groups-images-and-dast)
5. [How a run works](#how-a-run-works)
6. [Verdicts, exit codes and priorities](#verdicts-exit-codes-and-priorities)
7. [Output files](#output-files)
8. [Options](#options)
9. [Suppressing accepted risks](#suppressing-accepted-risks)
10. [Known issues and troubleshooting](#known-issues-and-troubleshooting)
11. [Safety rules](#safety-rules)
12. [Repository layout](#repository-layout)
13. [Limits and status](#limits-and-status)

---

## Requirements

- **Docker Desktop** (started automatically on Windows when a scan needs it)
- **.NET SDK 8+** (NuGet Audit and publishing .NET projects; not needed for non-.NET repos)
- **Node 20+** (runs the gate and builds the PDF)
- Edge or Chrome for the PDF (already on most machines)

No scanner is installed on the machine. Images are pulled on first use and pinned to tested versions:

| Tool | Image | Size |
|---|---|---|
| gitleaks | `ghcr.io/gitleaks/gitleaks:v8.30.1` | ~25 MB |
| OSV-Scanner | `ghcr.io/google/osv-scanner:v2.7.1` | small |
| Grype | `anchore/grype:v0.122.0` | ~31 MB |
| Trivy | `aquasec/trivy:0.76.2` | ~60 MB |
| Semgrep | `semgrep/semgrep:1.185.0` | ~414 MB |
| OWASP ZAP | `ghcr.io/zaproxy/zaproxy:stable` | ~1.1 GB (only for DAST) |

## Quick start

```bash
git clone <this-repo-url> Security-Gate-Skill
cd Security-Gate-Skill

# 1. Check Docker and the .NET SDK, list the images that will be pulled (changes nothing)
node security-gate/scripts/gate.mjs --preflight

# 2. Scan a project (the first run pulls the images and databases, so it is slow)
node security-gate/scripts/gate.mjs --root /path/to/your-project
```

Reports land in `<project>/.work/security-gate/`. Exit code: `0` PASS, `1` FAIL, `2` INCOMPLETE.

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

- `--agent all` = Claude Code + Codex + Antigravity (two folders: `.claude/skills` and `.agents/skills`; Cursor reads both). Add `cursor`
  explicitly to also create `.cursor/skills`: `--agent all,cursor`.
- `--agents-md` adds a short, idempotent "Security gate" block to the project's `AGENTS.md`, for agents or versions without skill support.
- `--force` replaces an existing copy; `--dry-run` shows what would happen. Restart the agent afterwards.

Then ask your agent: **"run the security gate"**. The skill tells the agent to tell you once what the first run downloads and wait for your
yes, to run the gate, read the report and summarise it, and never to print secrets or scan non-local DAST targets.

> The folder locations come from each product's documentation. The skill was run end to end in Claude Code; loading it inside Cursor,
> Codex and Antigravity has not been tested here.

## Scan groups, images and DAST

```bash
node security-gate/scripts/gate.mjs --root .                      # all = sca + sast + secrets + container
node security-gate/scripts/gate.mjs --root . --tool sca           # NuGet Audit + OSV-Scanner
node security-gate/scripts/gate.mjs --root . --tool sast          # Semgrep
node security-gate/scripts/gate.mjs --root . --tool secrets       # gitleaks
node security-gate/scripts/gate.mjs --root . --tool container     # Trivy + Grype on the source tree
node security-gate/scripts/gate.mjs --root . --tool container --image myapp:1.0   # also scan an image
node security-gate/scripts/gate.mjs --root . --tool dast --dast-url http://localhost:5170   # ZAP baseline (passive)
```

- A **local image** is scanned through the Docker socket; an image that is not local is pulled from the registry by the scanner.
- **DAST** needs the app running. Only `localhost`, `*.localhost` and `*.test` are accepted; any other host needs
  `--dast-allow-host <host>` and your confirmation that you own it. The **active** scan (`--dast-full`) also needs `--i-am-authorized`.
- `--tool` / `--only` give a **partial scan**: the report states which tools the verdict covers. `--skip` makes the gate `INCOMPLETE`.

## How a run works

1. **Docker**: starts Docker Desktop if needed, pulls missing images (sizes printed; `--no-pull` forbids it), records image digests.
2. **Publish (only for .NET)**: web/exe projects are published to a temp folder outside the repo so the dependency scanners can read
   `*.deps.json` (they do not read `.csproj`). The folder is deleted afterwards.
3. **Scan**: each tool runs in its container with the project mounted read-only. Output is parsed into one finding list.
4. **Suppressions** (`.security-gate/ignore.json`) are applied; only valid, unexpired entries count.
5. **Verdict + reports**: a finding at or above `--fail-on` (default `high`) is blocking.

## Verdicts, exit codes and priorities

| Verdict | Exit | Meaning |
|---|---|---|
| **PASS** | 0 | Every selected tool ran and nothing blocking was found |
| **FAIL** | 1 | At least one blocking finding |
| **INCOMPLETE** | 2 | A tool could not run (Docker down, image missing, error), had nothing to scan (`NO-COVERAGE`) or was skipped |

| Priority | Severity it covers | What to do |
|---|---|---|
| **L0 High** | Critical, High | Fix now. Any secret leak is L0: rotate the credential first |
| **L1 Medium** | Medium, and "unknown" severity | Fix in the current sprint |
| **L2 Low** | Low, Negligible | Track, fix when convenient |

## Output files

Written to `<project>/.work/security-gate/`:

| File | Content |
|---|---|
| `security-report.pdf` | Enterprise-style report: summary, findings by severity and category, "Fix first", a **clickable issue index** and **one numbered page per issue** (what it means, solution, affected items, links to the previous/next issue). Findings are ranked L0 / L1 / L2. |
| `report.md`, `report.json` | Same data as text / machine-readable (includes image digests) |
| `gitleaks-*.json`, `osv-*.json`, `grype-*.json`, `trivy-*.json`, `semgrep.json`, `nuget-*.json`, `zap.json/html` | Raw tool output |

The PDF is printed by the Edge or Chrome already on the machine. If none is found you get an HTML file to print yourself. Rebuild it any
time: `node security-gate/scripts/report-pdf.mjs <report.json> [out.pdf]`.

## Options

```text
node security-gate/scripts/gate.mjs [options]
  --root <dir>            project to scan (default: current folder)
  --out <dir>             report folder (default: <root>/.work/security-gate)
  --fail-on <level>       critical | high | medium | low   (default: high)
  --tool <groups>         all | sca | sast | secrets | container | dast  (comma list)
  --only a,b / --skip a   tools: gitleaks, nuget, semgrep, osv, grype, trivy, zap  (--skip makes the gate INCOMPLETE)
  --image <ref>           scan a container image (repeatable)
  --dast-url <url>        add OWASP ZAP against a running app (local targets only)
  --dast-full --i-am-authorized   ACTIVE ZAP scan (attack traffic): only for apps you own
  --dast-allow-host <h>   allow a non-local DAST host you own  (repeatable)
  --dast-minutes <n>      ZAP spider time (default 1)
  --preflight             check Docker/.NET and list images, change nothing
  --no-pull               never download images
  --no-publish            do not publish .NET projects
  --no-history            skip the gitleaks git-history scan
  --no-pdf                skip the PDF
  --semgrep-config <cfg>  other semgrep rule packs (repeatable), e.g. p/javascript
  --exclude <glob>        extra semgrep exclude (repeatable)
  --ignore <file>         suppressions file (default: <root>/.security-gate/ignore.json)
  --keep                  keep the temp publish folder
Environment: SECURITY_GATE_IMAGE_<TOOL> overrides an image, e.g. SECURITY_GATE_IMAGE_TRIVY=aquasec/trivy:latest
```

## Suppressing accepted risks

`<project>/.security-gate/ignore.json` (template: [`security-gate/references/ignore.example.json`](security-gate/references/ignore.example.json)).
Each entry needs `id`, a real `reason` and an `expires` date. Entries without these, or expired ones, are ignored and listed in the report
so the finding counts again. Suppressed findings stay visible in the report.

## Known issues and troubleshooting

Real problems found while testing on an Umbraco (.NET) project, and what to do:

- **gitleaks reports hundreds of `generic-api-key` hits in `uSync/**/*.config`.** Those lines hold Umbraco content GUIDs (`Key="..."`),
  not secrets (336 of 344 flagged lines contained only GUIDs; the other 8 were short lines that were not individually inspected). Suppress by
  `id` + `path` (`uSync/`) with a reason and expiry. The gate does **not** hide them by default.
- **OSV-Scanner flags NuGet packages with a 4-part version `x.y.z.0` (for example `10.0.0.0`).** That is the assembly version read from
  `deps.json`, not the package version, so it matches old advisories. The gate labels these "probable false positive"; confirm the real
  version with NuGet Audit (`dotnet list package --include-transitive`), then suppress.
- **Dependency scanners found nothing for .NET at first.** They read `deps.json` / `packages.lock.json`, not `.csproj`. Fixed by the publish
  step. Alternative: enable `RestorePackagesWithLockFile` and commit `packages.lock.json`.
- **Grype flags `Microsoft.AspNetCore.*` / `System.*` 10.0.13 files from `refs/`.** These are the installed .NET SDK / targeting-pack patch
  level, a real finding about the machine. Update the .NET SDK / runtime to the fixed patch.
- **Tooling folders were scanned.** OSV-Scanner initially scanned `.claude/**` lockfiles (about 94 npm findings of tooling, not product code).
  It now scans each top-level project folder and skips dot-folders, matching Semgrep, Grype and Trivy.
- **gitleaks history scan says "repository has no commits yet".** Expected before the first commit; only the working tree is scanned.
- **The first run is slow and large.** Image pulls plus the Grype and Trivy vulnerability databases (kept in the Docker volumes
  `security-gate-grype-db` and `security-gate-trivy-cache`; remove them with `docker volume rm` to free space).
- **"Docker is not running".** The gate starts Docker Desktop on Windows and waits up to ~3 minutes; elsewhere start Docker yourself.
- **ZAP cannot reach the app.** The app must listen on an address Docker can reach (for example `0.0.0.0` or `localhost`); `localhost` is
  rewritten to `host.docker.internal`.
- **No PDF produced.** Needs Edge or Chrome (`PDF_BROWSER` env var can point to a browser). The HTML is kept as fallback.
- **`INCOMPLETE` although nothing was found.** A tool could not run, had nothing to scan, or was skipped. Run `--preflight`.
- **A tool's output format changes.** The gate then reports `ERROR` for that tool instead of passing. Tested with the pinned images above and
  .NET SDK 10.0.402.

## Safety rules

- Scanners run in containers with the project mounted **read-only**. Only the report folder is writable.
- Secret values are never copied: gitleaks runs with `--redact`; Semgrep and Trivy findings are cut down to rule + location. Secret-bearing
  files (`appsettings.Development.json`, `.env*`, `*.pfx`, ...) are excluded from Semgrep.
- Local images are scanned through the Docker socket, which gives that container control of the Docker engine. Fine for these official
  images on a developer machine; avoid on shared CI runners (scan from the registry instead).
- DAST refuses non-local targets by default and never runs the active scan without `--i-am-authorized`.
- The scan makes network calls (image registries, nuget.org, Semgrep registry, vulnerability databases) and runs `dotnet restore` /
  `dotnet publish` on the scanned project.

## Repository layout

```
Security-Gate-Skill/
  README.md
  install-skill.mjs            copies the skill into Claude Code / Cursor / Codex / Antigravity folders
  docs/                        example report (png + pdf)
  security-gate/               <- the skill (Agent Skills format)
    SKILL.md                   instructions the agent follows
    scripts/gate.mjs           runner (Node 20+, no npm dependencies)
    scripts/report-pdf.mjs     PDF builder
    scripts/gate.selftest.mjs  offline self-test (node security-gate/scripts/gate.selftest.mjs)
    references/                tool details, ignore.json template
```

## Limits and status

- Scanners find **known** issues only. A PASS is not a penetration test; the ZAP baseline is passive and cannot log in.
- No reachability analysis: a blocking CVE in an unused code path still needs a reasoned suppression.
- OSV-Scanner, Grype and Trivy use different databases and can disagree; each is reported separately.
- Windows is the tested platform. Linux/macOS should work with Docker and Node, but are untested here.
- License: [MIT](LICENSE). The scanner images carry their own licenses.
