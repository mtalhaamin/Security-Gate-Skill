---
name: security-gate
description: >
  One security gate for a codebase: runs gitleaks (secrets, working tree + git history), NuGet Audit
  (dotnet list package --vulnerable, direct + transitive), semgrep (SAST), osv-scanner and grype
  (dependency CVEs) and returns a single PASS / FAIL / INCOMPLETE verdict with a report. Use when the
  user asks to run the security gate, scan the repo for secrets/vulnerabilities, check it is clean
  before commit/PR/release, or mentions gitleaks, semgrep, osv-scanner, grype or NuGet audit.
---

# security-gate

Self-contained and agent-neutral (Agent Skills format): works in Claude Code, Cursor, Codex and Antigravity.
The runner is a plain Node script, so any agent that can run a shell command can use it. Skill folders:
`.claude/skills/` (Claude Code), `.cursor/skills/` (Cursor), `.agents/skills/` (Codex, Antigravity, also read
by Cursor), `~/.gemini/antigravity/skills/` (Antigravity, global). The scanned project is passed with
`--root`; reports are written to `<root>/.work/security-gate/` (override with `--out`).

`<skill-dir>` below = the folder that contains this SKILL.md.

## Hard rules

1. **Never install or download anything without an explicit "yes" from the user in this session.** The
   runner itself installs nothing. If tools are missing, show the install commands and ask.
2. **Never read, print or paste secret values.** Report only rule id, file and line. Do not open
   `appsettings.Development.json`, `.env*`, `*.pfx`, user-secrets. Gitleaks runs with `--redact`;
   semgrep findings are reduced to rule + location (code lines are dropped by the runner).
3. **"Clean" means PASS from the runner.** Never say the repo is clean if the verdict is INCOMPLETE or
   FAIL, or if a tool was skipped, missing or reported no coverage.
4. Do not suppress a finding, lower `--fail-on`, or use `--skip` to get a green result unless the user
   asked for exactly that.

## Procedure

1. **Preflight** (from anywhere):
   `node <skill-dir>/scripts/gate.mjs --preflight`
   It lists each tool as OK or MISSING with the install command (winget / pip). If any are missing, tell
   the user which, give the commands, and ask whether to install them. After an install the user must open a
   new terminal (PATH). Do not continue to step 2 with missing tools unless the user accepts an INCOMPLETE run.
2. **Run** from the project root (or pass `--root`):
   `node <skill-dir>/scripts/gate.mjs --root <project> --fail-on high`
   - The first grype run downloads its vulnerability DB (large) and semgrep downloads rule packs; the
     whole run can take several minutes. Run it in the background if it may exceed 2 minutes.
   - For .NET repos the runner publishes web/exe projects to a temp folder (outside the repo, deleted
     afterwards) so osv-scanner and grype can read `*.deps.json`. `--no-publish` skips that.
   - Useful flags: `--only gitleaks,nuget` / `--skip semgrep` (makes the gate INCOMPLETE),
     `--fail-on critical|high|medium|low`, `--no-history`, `--semgrep-config p/<ruleset>`, `--keep`.
3. **Report files** are written automatically to `<out>/`: `security-report.pdf` (key points, per-tool table,
   findings grouped by priority **L0 = High, L1 = Medium, L2 = Low**, each with the action to take), `report.md`,
   `report.json` and the raw tool outputs. The PDF is printed with the installed Edge/Chrome (no extra install);
   `--no-pdf` turns it off. Priority mapping: L0 = critical + high severity, L1 = medium (and unknown), L2 = low.
   To rebuild only the PDF: `node <skill-dir>/scripts/report-pdf.mjs <out>/report.json [out.pdf]`.
   **Read** `<out>/report.md` and answer the user in at most ~15 lines: verdict, one line per tool
   (PASS / FAIL / NOT-RUN / ERROR / NO-COVERAGE), the top blocking findings (id, package or file:line,
   fixed version if known), and what the user must do themself (rotate leaked credentials, approve installs).
4. **Fix loop** when asked to fix: see "Fixing" below, then re-run the gate until PASS. Report any
   remaining finding honestly instead of suppressing it.

## Verdict and exit codes

| Verdict | Exit | Meaning |
|---|---|---|
| PASS | 0 | Every selected tool ran, nothing at or above `--fail-on` (default `high`) after valid suppressions |
| FAIL | 1 | At least one blocking finding |
| INCOMPLETE | 2 | A tool is missing, errored, found nothing to scan (`NO-COVERAGE`), or was skipped. Not a pass |

`N/A` (only NuGet on a non-.NET repo) does not block. Severity unknown from a tool is treated as `medium`
and marked `?` in the report.

## Fixing (by tool)

- **gitleaks FAIL**: a committed secret is compromised even after deletion. Tell the user to **rotate it
  first**, then remove it from the code (config / env / Key Vault). History rewrite or force-push only if
  the user explicitly asks. Never use `--no-verify` or `gitleaks:allow` comments to get past it.
- **nuget / osv / grype FAIL**: bump the package to the fixed version (for transitive ones add a direct
  `PackageVersion` pin in `Directory.Packages.props`), rebuild, run tests, re-run the gate. If no fix exists,
  record a time-limited suppression (below) with the user's agreement.
- **semgrep FAIL**: read the rule and the code, fix the cause. A false positive may get a
  `# nosemgrep: <rule-id>` comment with a reason, or a suppression entry, only with the user's agreement.

## Suppressions (accepted risk)

File `<root>/.security-gate/ignore.json` (see `references/ignore.example.json`). Each entry needs `id`,
a real `reason` and an `expires` date (YYYY-MM-DD); entries without these, or expired, are ignored and listed
in the report so the finding counts again. Suppressed findings stay visible in the report.

## Limits to tell the user

- osv-scanner and grype only see .NET packages through lockfiles or `deps.json`; the publish step provides
  that. If publish fails, the report says so and those two tools may end as NO-COVERAGE.
- Gitleaks `git` needs at least one commit; a repo without commits gets a working-tree scan only (noted).
- Scanners report known issues only. A PASS is not a penetration test or a guarantee.
- Details, install table, CI usage and tool-specific notes: `references/tools.md`.

## Self-test (no scanners needed)

`node <skill-dir>/scripts/gate.selftest.mjs` checks the parsers, suppression and verdict logic offline.
