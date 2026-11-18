---
name: security-gate
description: >
  One security gate for a codebase, run through official Docker images: OSV-Scanner + NuGet Audit (SCA), Semgrep (SAST),
  gitleaks (secrets), Trivy + Grype (dependencies, IaC, container images) and OWASP ZAP (DAST, local targets only). Returns a single
  PASS / FAIL / INCOMPLETE verdict and a PDF report that ranks findings L0 High / L1 Medium / L2 Low. Use when the user asks to run the
  security gate, scan the repo or a container image for secrets/vulnerabilities, run DAST/ZAP, check it is clean before a
  commit/PR/release, or mentions gitleaks, semgrep, osv-scanner, grype, trivy, ZAP or NuGet audit.
---

# security-gate

Agent-neutral (Agent Skills format): works in Claude Code, Cursor, Codex and Antigravity. The runner is a plain Node script, so any
agent that can run a shell command can use it. Skill folders: `.claude/skills/` (Claude Code), `.cursor/skills/` (Cursor),
`.agents/skills/` (Codex, Antigravity, also read by Cursor), `~/.gemini/antigravity/skills/` (Antigravity, global).

Every scanner runs in its **official Docker image**; nothing is installed on the machine. Needs **Docker Desktop**, the **.NET SDK**
(NuGet Audit and publish) and **Node 20+**. The scanned project is passed with `--root`; reports go to `<root>/.work/security-gate/`.

`<skill-dir>` below = the folder that contains this SKILL.md.

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

## Procedure

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

File `<root>/.security-gate/ignore.json` (see `references/ignore.example.json`). Each entry needs `id`, a real `reason` and an `expires`
date (YYYY-MM-DD); entries without these, or expired, are ignored and listed in the report so the finding counts again. Suppressed
findings stay visible in the report.

## Limits to tell the user

- OSV-Scanner, Grype and Trivy read .NET packages from `deps.json` / lock files; the runner publishes web/exe projects to a temp
  folder (outside the repo, deleted afterwards) to provide that. If publish fails the report says so.
- Gitleaks `git` needs at least one commit; a repo without commits gets a working-tree scan only (noted).
- Scanners report known issues only. A PASS is not a penetration test; the ZAP baseline is passive only.
- Details, image list, severity mapping, CI use: `references/tools.md`.

## Self-test (no Docker needed)

`node <skill-dir>/scripts/gate.selftest.mjs` checks the parsers, tool selection, DAST safety, suppression and verdict logic offline.
