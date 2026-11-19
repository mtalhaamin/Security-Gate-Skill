---
name: security-gate
description: >
  Use to security-scan a codebase or container image before a commit, PR or release. Runs gitleaks, Semgrep, OSV-Scanner,
  NuGet Audit, Trivy, Grype and OWASP ZAP in Docker; gives PASS/FAIL and a PDF.
license: MIT
compatibility: Needs Docker, Node 20+ and a shell. The .NET SDK is needed only for .NET projects.
metadata:
  author: Muhammad Talha (mtalhaamin)
  version: "1.2.0"
  tags: [security, sast, sca, dast, owasp]
---

# security-gate

## Purpose

One command that checks a project for security problems before it goes live: leaked secrets, vulnerable libraries, risky code,
container and IaC settings and, if asked, a scan of the running web app. It gives one PASS / FAIL / INCOMPLETE verdict and a PDF
report mapped to the OWASP Top 10:2025.

Works in any agent that can run a shell command (Claude Code, Cursor, Codex, Antigravity and others). Skill folders:
`.claude/skills/` (Claude Code), `.cursor/skills/` (Cursor), `.agents/skills/` (Codex, Antigravity, also read by Cursor),
`~/.gemini/antigravity/skills/` (Antigravity, global).

## Prerequisites

- **Docker Desktop** (or another Docker engine). Every scanner runs in its official Docker image; nothing else is installed.
- **Node 20+** to run the scripts.
- **.NET SDK 8+** only for .NET projects (NuGet Audit and publish).
- No API keys or accounts.

The scanned project is passed with `--root`; reports go to `<root>/.work/security-gate/`.
`<skill-dir>` below = the folder that contains this SKILL.md.

## Available Scripts

| Script | Purpose | Arguments |
|---|---|---|
| `scripts/gate.mjs` | Runs the scanners and writes the reports | `--root <project>`, `--tool <groups>`, `--image <name:tag>`, `--dast-url <url>`, `--fail-on <level>`, `--preflight` (see Instructions) |
| `scripts/report-pdf.mjs` | Rebuilds only the PDF from a saved report | `<out>/report.json [out.pdf]` |
| `scripts/gate.selftest.mjs` | Offline self-test, no Docker needed | none |
| `scripts/app-start.mjs` | Used by `--dast-auto` to start and stop the app | none (not run directly) |

## Hard rules

1. **First run downloads images: ask once, then proceed.** Before the first run tell the user which images will be pulled and their size
   (`--preflight` lists them: gitleaks ~25 MB, semgrep ~414 MB, grype ~31 MB, trivy ~60 MB, osv-scanner small, ZAP ~1.1 GB and only for
   DAST) and wait for a yes. After that the images are local and no further question is needed. `--no-pull` forbids downloads.
2. **DAST is for targets the user owns.** ZAP sends attack-style traffic. Only `localhost`, `*.localhost` and `*.test` are accepted; any
   other host needs the user to say they own/are authorised to test it (`--dast-allow-host <host>`). The active scan (`--dast-full`) needs
   the user to ask for it explicitly plus `--i-am-authorized`. Default is the passive baseline scan.
3. **Never read, print or paste secret values.** Report only rule id, file and line. Do not open `appsettings.Development.json`, `.env*`,
   `*.pfx`, user-secrets. Gitleaks runs with `--redact`; semgrep and Trivy findings are cut down to rule + location.
4. **"Clean" means PASS from the runner.** Never say the repo is clean if the verdict is INCOMPLETE or FAIL, if a tool was skipped or
   not run, or if the report says "Partial scan by request" (then say which tools the verdict covers).
5. Do not suppress a finding, lower `--fail-on`, or use `--skip` to get a green result unless the user asked for exactly that.

## Instructions

1. **Preflight** (changes nothing): `node <skill-dir>/scripts/gate.mjs --preflight` shows Docker, the .NET SDK and which images are
   already local or will be pulled. Docker Desktop is started automatically on a real run (Windows).
2. **Run** from the project root (or pass `--root`):
   `node <skill-dir>/scripts/gate.mjs --root <project>`
   - Default `--tool all` = **sca** (NuGet Audit + OSV-Scanner), **sast** (Semgrep), **secrets** (gitleaks), **container** (Trivy + Grype
     on the source tree and, for .NET, the published output). Pick groups with `--tool sca|sast|secrets|container|dast[,..]`.
   - **Image scan**: `--image myapp:tag` (repeatable). A local image is scanned through the Docker socket, otherwise from the registry.
   - **DAST**: start the app locally, then `--dast-url http://localhost:PORT` (adds ZAP; `--tool dast` runs only ZAP). Or let the gate start it: `--dast-auto --i-trust-this-repo` (ASP.NET Core, Node.js, Django; it finds the start command, picks a free port, runs it without a shell, stops the app afterwards) or `--dast-start "<command with {port}>"` for any other stack. Both run the project's own code, so **ask the user first** and pass `--i-trust-this-repo` only after they agree.
   - The first run is slow (image pulls, Semgrep rules, Trivy/Grype databases); run it in the background if it may exceed 2 minutes.
   - Other flags: `--fail-on critical|high|medium|low` (default high), `--skip a,b` (makes the gate INCOMPLETE), `--no-history`,
     `--no-publish`, `--semgrep-config p/<ruleset>` (replaces the automatic rules) or `--semgrep-extra p/<ruleset>` (adds to them), `--no-pdf`, `--keep`.
3. **Reports** are written automatically to `<out>/`: `security-report.pdf` (key points, "Fix first" table, per-tool status, findings
   grouped **L0 = High, L1 = Medium, L2 = Low** with the action for each), `report.md`, `report.json` and raw tool output.
   L0 = critical + high severity, L1 = medium (and unknown), L2 = low. Rebuild only the PDF with
   `node <skill-dir>/scripts/report-pdf.mjs <out>/report.json [out.pdf]`.
   **Read** `<out>/report.md` and answer in at most ~15 lines: verdict and security grade (A-E, score /100), one line per tool, the top blocking findings (id, package or
   file:line, fixed version if known), and what the user must do themself (rotate leaked credentials, approve downloads).
4. **Fix loop** when asked to fix: see "Fixing" below, then re-run the gate until PASS. Report any remaining finding honestly instead of
   suppressing it.

## Examples

Full scan of a project (all groups except DAST):

```bash
node <skill-dir>/scripts/gate.mjs --root ./my-project
```

Only secrets and code checks, failing on medium and above:

```bash
node <skill-dir>/scripts/gate.mjs --root ./my-project --tool secrets,sast --fail-on medium
```

Scan a container image, then a web app already running on port 5000:

```bash
node <skill-dir>/scripts/gate.mjs --root ./my-project --image myapp:1.0
node <skill-dir>/scripts/gate.mjs --root ./my-project --dast-url http://localhost:5000
```

Example answer to the user after a run:

```text
Verdict: FAIL (grade D, 77/100), 5 of 6 checks ran.
- gitleaks: PASS. Semgrep: PASS. OSV/Grype: 0 blocking.
- Trivy: 1 high, KSV-0014 (k8s/deployment.yml:20): set readOnlyRootFilesystem: true.
Report: .work/security-gate/security-report.pdf
```

## Verdict and exit codes

| Verdict | Exit | Meaning |
|---|---|---|
| PASS | 0 | Every selected tool ran, nothing at or above `--fail-on` (default `high`) after valid suppressions |
| FAIL | 1 | At least one blocking finding |
| INCOMPLETE | 2 | A tool could not run (Docker down, image missing, error), found nothing to scan (`NO-COVERAGE`), or was skipped with `--skip` |

`N/A` (NuGet on a non-.NET repo) does not block. Unknown severity from a tool is treated as `medium` and marked `?`.

The report also gives a **security grade A-E** (SonarQube's rule: E any critical, D any high, C any medium, B only low, A none; capped
at C when a check did not run) and a **score 0-100** (100 minus 25 per critical issue, 10 per high up to 60, 3 per medium up to 30,
1 per low up to 10). The grade never changes the verdict; the verdict still comes only from `--fail-on`.

Every finding is mapped to an **OWASP Top 10:2025** category (official CWE lists in `references/owasp-top10-2025.json`;
vulnerable libraries count as A03, IaC settings as A02, leaked secrets as A07 via CWE-798). The PDF has a coverage table for
all 10 categories. Never claim the project "passes the OWASP Top 10": A06 Insecure Design and A09 Logging need a manual review,
and A01 Broken Access Control is only partly covered by scanners.

## Fixing (by tool)

- **gitleaks / Trivy secret FAIL**: a committed secret is compromised even after deletion. Tell the user to **rotate it first**, then remove
  it from the code (config / env / Key Vault). History rewrite or force-push only if the user explicitly asks. Never use `--no-verify`
  or `gitleaks:allow` comments to get past it.
- **nuget / osv / grype / trivy dependency FAIL**: bump the package to the fixed version (for transitive ones add a direct
  `PackageVersion` pin in `Directory.Packages.props`), rebuild, run tests, re-run. If no fix exists, record a time-limited suppression
  with the user's agreement.
- **Trivy misconfiguration / semgrep FAIL**: read the rule and the code or Dockerfile/IaC, fix the cause. A false positive may get a
  `# nosemgrep: <rule-id>` comment with a reason, or a suppression entry, only with the user's agreement.
- **ZAP findings**: fix the web issue (headers, CSRF tokens, cookies, ...) and re-run the DAST scan to confirm.

## Suppressions (accepted risk)

File `<root>/.security-gate/ignore.json` (see `assets/ignore.example.json`). Each entry needs `id`, a real `reason` and an `expires`
date (YYYY-MM-DD); entries without these, or expired, are ignored and listed in the report so the finding counts again. Suppressed
findings stay visible in the report.

## Limitations

Tell the user these when they matter:

- OSV-Scanner, Grype and Trivy read .NET packages from `deps.json` / lock files; the runner publishes web/exe projects to a temp
  folder (outside the repo, deleted afterwards) to provide that. If publish fails the report says so.
- Gitleaks `git` needs at least one commit; a repo without commits gets a working-tree scan only (noted).
- Scanners report known issues only. A PASS is not a penetration test; the ZAP baseline is passive only.
- Gitleaks finds only secrets that match its rules. The gate adds one rule for signed Power Automate / Logic Apps links;
  other custom secrets can still be missed. A project's own `.gitleaks.toml` replaces the gate's config (and this extra rule).
- Scanning a local Docker image mounts the Docker socket into the Trivy and Grype containers (official pinned images only).
- Details, image list, severity mapping, CI use: `references/tools.md`.

## Troubleshooting

| Error | Cause | Solution |
|---|---|---|
| `Docker is not running and could not be started` | Docker Desktop is closed or still starting | Start Docker Desktop, wait until it is ready, run again |
| `... is not pulled and --no-pull was given` | A scanner image is not on this computer | Ask the user, then run without `--no-pull` (`--preflight` shows sizes) |
| NuGet shows `needs .NET SDK 8+` or `dotnet restore failed` | .NET SDK missing or the project does not restore | Install the .NET SDK 8+ or fix the restore error, run again |
| Semgrep `ERROR` with `rule/config error(s)` | Rules could not be downloaded or a custom ruleset is wrong | Check the network and `--semgrep-config`; details are in `semgrep.json` |
| A tool shows `NO-COVERAGE` | No lock files or manifests found for that tool | Check `--root` points at the project; restore or build first |
| `refusing to scan <host>` | DAST target is not localhost | Use a local URL, or `--dast-allow-host <host>` only if the user owns that host |
| `git history: repository has no commits yet` | New repo without commits | Normal: the working tree is still scanned |

## Self-test (no Docker needed)

`node <skill-dir>/scripts/gate.selftest.mjs` checks the parsers, tool selection, DAST safety, suppression and verdict logic offline.
