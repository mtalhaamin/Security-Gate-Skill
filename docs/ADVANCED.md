# Security Gate: advanced guide

The simple guide is in the [README](../README.md). This page has every option, the problems we met while testing, and the safety rules.

## All options

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

## Tool groups

| `--tool` | Runs | Looks for |
|---|---|---|
| `sca` | NuGet Audit + OSV-Scanner | known-vulnerable libraries |
| `sast` | Semgrep | insecure code |
| `secrets` | gitleaks | passwords / keys in code and git history |
| `container` | Trivy + Grype | libraries, Dockerfile / IaC mistakes, images |
| `dast` | OWASP ZAP | a running website (needs `--dast-url`) |
| `all` (default) | sca + sast + secrets + container | everything except DAST |

`--tool` / `--only` give a **partial scan**: the report says which tools the verdict covers. `--skip` makes the gate `INCOMPLETE`.

## Docker images (pinned to tested versions)

| Tool | Image | Size |
|---|---|---|
| gitleaks | `ghcr.io/gitleaks/gitleaks:v8.30.1` | ~25 MB |
| OSV-Scanner | `ghcr.io/google/osv-scanner:v2.7.1` | small |
| Grype | `anchore/grype:v0.122.0` | ~31 MB |
| Trivy | `aquasec/trivy:0.76.2` | ~60 MB |
| Semgrep | `semgrep/semgrep:1.185.0` | ~414 MB |
| OWASP ZAP | `ghcr.io/zaproxy/zaproxy:stable` | ~1.1 GB (only for DAST) |

NuGet Audit uses your .NET SDK, no image. Images are pulled on first use; `--no-pull` forbids it.

## How a run works

1. **Docker**: starts Docker Desktop if needed, pulls missing images, records image digests.
2. **Publish (.NET only)**: web/exe projects are published to a temp folder outside the repo so the dependency scanners can read `*.deps.json` (they do not read `.csproj`). The folder is deleted afterwards.
3. **Scan**: each tool runs in its container with the project mounted read-only. Output is parsed into one finding list.
4. **Suppressions** (`.security-gate/ignore.json`) are applied.
5. **Verdict + reports**: a finding at or above `--fail-on` is blocking.

## Verdicts, exit codes and priorities

| Verdict | Exit | Meaning |
|---|---|---|
| PASS | 0 | Every selected tool ran and nothing blocking was found |
| FAIL | 1 | At least one blocking finding |
| INCOMPLETE | 2 | A tool could not run (Docker down, image missing, error), had nothing to scan, or was skipped |

| Priority | Severity | What to do |
|---|---|---|
| L0 High | Critical, High | Fix now. Any secret leak is L0: rotate the credential first |
| L1 Medium | Medium, unknown | Fix in the current sprint |
| L2 Low | Low, Negligible | Track, fix when convenient |

## Output files

In `<project>/.work/security-gate/`:

| File | Content |
|---|---|
| `security-report.pdf` | The report: summary, findings by severity and category, "Fix first", a clickable issue index and one numbered page per issue |
| `report.md`, `report.json` | Same data as text / machine-readable (includes image digests) |
| `gitleaks-*.json`, `osv-*.json`, `grype-*.json`, `trivy-*.json`, `semgrep.json`, `nuget-*.json`, `zap.json/html` | Raw tool output |

Rebuild the PDF any time: `node security-gate/scripts/report-pdf.mjs <report.json> [out.pdf]`.

## Hiding false alarms (suppressions)

Create `<project>/.security-gate/ignore.json` (template: [`security-gate/references/ignore.example.json`](../security-gate/references/ignore.example.json)). Each entry needs `id`, a real `reason` and an `expires` date. Entries without these, or expired ones, are ignored and listed in the report so the finding counts again. Suppressed findings stay visible in the report.

## Use it in your AI coding tool

```bash
node install-skill.mjs --agent all --project /path/to/project --agents-md
```

| Tool | Project folder | Global folder (`--global`) | Flag |
|---|---|---|---|
| Claude Code | `.claude/skills/security-gate` | `~/.claude/skills` | `--agent claude` |
| Cursor | `.cursor/skills/security-gate` (also reads `.claude/skills` and `.agents/skills`) | `~/.cursor/skills` | `--agent cursor` |
| Codex | `.agents/skills/security-gate` | `~/.agents/skills` | `--agent codex` |
| Antigravity | `.agents/skills/security-gate` (legacy `.agent/skills` still read) | `~/.gemini/antigravity/skills` | `--agent antigravity` |

`--agent all` = Claude Code + Codex + Antigravity (Cursor reads both folders; add `cursor` to also create `.cursor/skills`). `--agents-md` adds a short block to the project's `AGENTS.md`. `--force` replaces an existing copy; `--dry-run` shows what would happen. Restart the tool afterwards. The folder locations come from each product's documentation; the skill was run end to end in Claude Code only.

## Known issues and troubleshooting

Real problems found while testing on an Umbraco (.NET) project:

- **gitleaks reports hundreds of `generic-api-key` hits in `uSync/**/*.config`.** Those lines hold Umbraco content GUIDs, not secrets (336 of 344 flagged lines contained only GUIDs; the other 8 were short lines not inspected one by one). Hide them with a suppression (`id` + `path`) and a reason. The gate does not hide them by default.
- **OSV-Scanner flags NuGet packages with a 4-part version like `10.0.0.0`.** That is the assembly version, not the package version, so it matches old advisories. The report labels these "probable false positive"; confirm the real version with `dotnet list package --include-transitive`.
- **Dependency scanners found nothing for .NET at first.** They read `deps.json` / `packages.lock.json`, not `.csproj`. Fixed by the publish step.
- **Grype flags `Microsoft.AspNetCore.*` / `System.*` 10.0.13 files from `refs/`.** That is the installed .NET SDK / targeting-pack patch level, a real finding about the machine. Update the .NET SDK.
- **Tooling folders were scanned.** OSV-Scanner initially scanned `.claude/**` lockfiles. It now scans each top-level project folder and skips dot-folders.
- **"repository has no commits yet".** Expected before the first commit; only the working tree is scanned.
- **The first run is slow and large.** Image pulls plus the Grype and Trivy databases (kept in the Docker volumes `security-gate-grype-db` and `security-gate-trivy-cache`; remove them with `docker volume rm` to free space).
- **"Docker is not running".** The gate starts Docker Desktop on Windows and waits up to ~3 minutes; elsewhere start Docker yourself.
- **ZAP cannot reach the app.** The app must listen on an address Docker can reach; `localhost` is rewritten to `host.docker.internal`.
- **No PDF.** Needs Edge or Chrome (`PDF_BROWSER` env var can point to a browser). The HTML is kept as fallback.
- **`INCOMPLETE` although nothing was found.** A tool could not run, had nothing to scan, or was skipped. Run `--preflight`.
- **A tool's output format changes.** The gate reports `ERROR` for that tool instead of passing. Tested with the pinned images above and .NET SDK 10.0.402.

## Safety rules

- Scanners run in containers with the project mounted **read-only**. Only the report folder is writable.
- Secret values are never copied: gitleaks runs with `--redact`; Semgrep and Trivy findings are cut down to rule + location. Secret files (`appsettings.Development.json`, `.env*`, `*.pfx`, ...) are excluded from Semgrep.
- Local images are scanned through the Docker socket, which gives that container control of the Docker engine. Fine on a developer machine; avoid on shared CI runners (scan from the registry instead).
- DAST refuses non-local targets by default and never runs the active scan without `--i-am-authorized`.
- A scan makes network calls (image registries, nuget.org, Semgrep registry, vulnerability databases) and runs `dotnet restore` / `dotnet publish` on the scanned project.

## Repository layout

```
Security-Gate-Skill/
  README.md                    simple guide
  install-skill.mjs            copies the skill into Claude Code / Cursor / Codex / Antigravity folders
  docs/                        this guide + example report (png, pdf)
  security-gate/               the skill (Agent Skills format)
    SKILL.md                   instructions the AI tool follows
    scripts/gate.mjs           the scanner runner (Node 20+, no npm packages)
    scripts/report-pdf.mjs     PDF builder
    scripts/gate.selftest.mjs  offline self-test
    references/                tool details, ignore.json template
```

## Limits

- Scanners find **known** issues only. A PASS is not a penetration test; the ZAP baseline is passive and cannot log in.
- No reachability analysis: a blocking CVE in an unused code path still needs a reasoned suppression.
- OSV-Scanner, Grype and Trivy use different databases and can disagree; each is reported separately.
- Windows is the tested platform. Linux/macOS should work with Docker and Node, but are untested here.
