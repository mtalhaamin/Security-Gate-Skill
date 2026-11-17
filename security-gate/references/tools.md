# security-gate: tool details (Docker-first)

Every scanner runs in its **official Docker image**; nothing is installed on the machine. Requirements: Docker Desktop, the .NET SDK
(NuGet Audit and publish), Node 20+. The project is mounted read-only at `/src`, the report folder at `/out`, the published .NET output
at `/pub`. Images are pulled on first use (`--no-pull` forbids it) and pinned to the versions this skill was tested with.

## Images

| Tool | Image (default pin) | Size | Override env var |
|---|---|---|---|
| gitleaks | `ghcr.io/gitleaks/gitleaks:v8.30.1` | ~25 MB | `SECURITY_GATE_IMAGE_GITLEAKS` |
| OSV-Scanner | `ghcr.io/google/osv-scanner:v2.7.1` | small | `SECURITY_GATE_IMAGE_OSV` |
| Grype | `anchore/grype:v0.122.0` | ~31 MB | `SECURITY_GATE_IMAGE_GRYPE` |
| Trivy | `aquasec/trivy:0.76.2` | ~60 MB | `SECURITY_GATE_IMAGE_TRIVY` |
| Semgrep | `semgrep/semgrep:1.185.0` | ~414 MB | `SECURITY_GATE_IMAGE_SEMGREP` |
| OWASP ZAP | `ghcr.io/zaproxy/zaproxy:stable` | ~1.1 GB (DAST only) | `SECURITY_GATE_IMAGE_ZAP` |
| NuGet Audit | none: runs with your .NET SDK (`dotnet list package --vulnerable`) | | |

Pins keep results reproducible. To use newer scanners set the env var (for example `SECURITY_GATE_IMAGE_TRIVY=aquasec/trivy:latest`).
The report records each image digest. Databases/rules (Trivy, Grype, Semgrep) are fetched fresh on use; Grype and Trivy keep their
caches in the Docker volumes `security-gate-grype-db` and `security-gate-trivy-cache`.

## Tool groups (same names as the team's `scan.ps1`)

| `--tool` | Runs | Covers |
|---|---|---|
| `sca` | NuGet Audit + OSV-Scanner | known-vulnerable packages |
| `sast` | Semgrep | insecure code (security-audit, OWASP Top 10, C#, secrets rule packs) |
| `secrets` | gitleaks | hard-coded secrets, working tree + git history |
| `container` | Trivy + Grype | dependencies, IaC / Dockerfile misconfigurations, secrets (Trivy), container images (`--image`) |
| `dast` | OWASP ZAP | running web app (needs `--dast-url`) |
| `all` (default) | sca + sast + secrets + container | everything except DAST |

`--dast-url` adds ZAP to any selection. `--tool` / `--only` produce a **partial scan**: the report says which tools the verdict covers.
`--skip` makes the gate INCOMPLETE.

## What each step runs

| Tool | Command (simplified) | Notes |
|---|---|---|
| gitleaks | `gitleaks dir` and `gitleaks git` with a generated config, `--redact`, `--exit-code 2` | Exit 2 = leaks, 1 = tool error. The config is default rules plus an allow-list of git-ignored paths (gitleaks does not read `.gitignore`). A project `.gitleaks.toml` is used instead if present. History scan only when the repo has commits. |
| NuGet Audit | `dotnet restore`, then `dotnet list <sln> package --vulnerable --include-transitive --format json` | Direct + transitive. If the advisory source is unreachable (NU1900) the step is ERROR, never PASS. |
| Semgrep | `semgrep scan --metrics=off --json ... --config p/security-audit --config p/owasp-top-ten --config p/csharp --config p/secrets` | Excludes `node_modules bin obj .git .work .claude` and secret files. Override packs with `--semgrep-config`. |
| OSV-Scanner | `osv-scanner scan source -r /src/<folder>` per top-level project folder, plus each published project | Dot-folders are skipped. Exit 128 = nothing to scan there. All targets 128 = NO-COVERAGE. |
| Grype | `grype dir:/src` and `dir:/pub/<project>`; images: `docker:<img>` (local) or `registry:<img>` | Severity gating is done by the runner. |
| Trivy | `trivy fs --scanners vuln,misconfig,secret` on the source; `vuln` on published output; `trivy image` for `--image` | Secret findings never include the matched text. |
| ZAP | `zap-baseline.py -t <url> -J zap.json -I` (passive). `zap-full-scan.py` only with `--dast-full --i-am-authorized` | `localhost` is rewritten to `host.docker.internal` for the container. Informational alerts are skipped. |

Local container images are scanned through the Docker socket (`/var/run/docker.sock`), which gives that container control of your Docker
engine: acceptable for these official images on a dev machine, avoid on shared CI runners. An image that is not local is pulled from the
registry by the scanner instead (public registries only).

## Why a publish step

NuGet dependencies are only in `.csproj` / `Directory.Packages.props`, which OSV-Scanner, Grype and Trivy do not read (they read
`packages.lock.json` and `*.deps.json`). The runner therefore runs `dotnet publish -c Release` for web/exe projects (test projects
excluded) into a temp folder outside the repo, mounts it at `/pub`, and deletes it afterwards (`--keep` leaves it). Alternative: enable lock
files (`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`) and commit `packages.lock.json`; then `--no-publish` is enough.

## Severity mapping

- gitleaks: every finding is `critical`. Trivy secrets: the rule's severity.
- NuGet: Critical, High, Moderate to medium, Low.
- Semgrep: ERROR to high, WARNING to medium, INFO to low.
- OSV-Scanner: CVSS score of the vulnerability group (9+ critical, 7+ high, 4+ medium, else low), else the database severity.
- Grype / Trivy: Critical, High, Medium, Low; Negligible to low.
- ZAP: risk code 3 high, 2 medium, 1 low (informational skipped).
- Unknown from any tool is treated as medium. Default gate threshold is `high` (`--fail-on`).

## Optional hardening for .NET projects (apply only with the owner's approval)

```xml
<!-- Directory.Build.props -->
<PropertyGroup>
  <NuGetAudit>true</NuGetAudit>
  <NuGetAuditMode>all</NuGetAuditMode>
  <NuGetAuditLevel>low</NuGetAuditLevel>
  <WarningsAsErrors>$(WarningsAsErrors);NU1902;NU1903;NU1904</WarningsAsErrors>
</PropertyGroup>
```

This makes `dotnet build` itself fail on vulnerable packages, so the problem appears before the gate runs.

## CI

```bash
node security-gate/scripts/gate.mjs --root . --fail-on high   # exit 0 pass, 1 fail, 2 incomplete
```

The runner needs Docker, the .NET SDK and Node on the build agent. Upload `.work/security-gate/` as a build artifact and treat exit code 2
as a failed build too.

## Known limits

- Output parsing follows each tool's JSON and was checked against real runs of the pinned versions. If a tool changes its output the runner
  reports ERROR for that tool instead of passing. `node scripts/gate.selftest.mjs` covers the logic offline.
- OSV-Scanner, Grype and Trivy use different databases and can disagree; each is reported separately.
- Reachability is not analysed; a blocking CVE in an unused code path still needs a reasoned suppression.
- ZAP baseline is passive and cannot log in to the target app; it finds issues visible without authentication.
