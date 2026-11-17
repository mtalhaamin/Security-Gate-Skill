# security-gate: tool details

## Install (Windows; nothing is installed by the runner)

| Tool | Command | Checked |
|---|---|---|
| gitleaks | `winget install Gitleaks.Gitleaks` (or `choco install gitleaks`) | winget id and choco package exist |
| osv-scanner | `winget install Google.OSVScanner` | winget id exists (choco's is an old 1.x, avoid) |
| grype | `winget install Anchore.Grype` (or `choco install grype`) | winget id and choco package exist |
| semgrep | `pip install semgrep` or `pipx install semgrep` | install path per Semgrep docs; native Windows support is not confirmed there, if it fails use WSL or Docker (`docker run --rm -v "%cd%:/src" semgrep/semgrep semgrep scan ...`) |
| NuGet audit | .NET SDK 8+ (built in) | needs `dotnet list package --format json` |

Open a new terminal after installing so PATH picks the tools up. Run `node scripts/gate.mjs --preflight` to verify.

## What each step runs

| Tool | Command (simplified) | Notes |
|---|---|---|
| gitleaks | `gitleaks dir --config <generated> --redact --exit-code 2 -f json -r <out>/gitleaks-dir.json .` and `gitleaks git ...` | Exit 2 = leaks, 1 = tool error. A config is generated: default rules + allow-list of git-ignored paths (gitleaks does not read `.gitignore`). A project `.gitleaks.toml` is used instead if present. History scan only when the repo has commits. |
| nuget | `dotnet restore <sln>`, then `dotnet list <sln> package --vulnerable --include-transitive --format json` | Direct + transitive. If the advisory source is unreachable (NU1900) the step is ERROR, never PASS. |
| semgrep | `semgrep scan --metrics=off --json ... --config p/security-audit --config p/owasp-top-ten --config p/csharp --config p/secrets .` | Excludes `node_modules bin obj .git .work .claude` and secret files. Rule packs are downloaded. Override packs with `--semgrep-config`. |
| osv-scanner | `osv-scanner scan source -r <top-level folder> --format json` per project folder (dot-folders like `.claude` are skipped) and for each published project | Exit 128 = no packages found there (not an error). All targets 128 = NO-COVERAGE. |
| grype | `grype dir:<dir> -o json -q` for the repo and each published project | First run downloads the vulnerability DB. Severity gating is done by the runner, not `--fail-on`. |

## Why a publish step

NuGet dependencies are only in `.csproj` / `Directory.Packages.props`, which osv-scanner and grype do not
read (they read `packages.lock.json` and `*.deps.json`). The runner therefore runs `dotnet publish -c Release`
for web/exe projects (test projects excluded) into a temp folder outside the repo and points both tools at it.
The folder is deleted afterwards (`--keep` leaves it). Alternative: enable lock files
(`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`) and commit `packages.lock.json`; then the
repo scan alone covers NuGet and `--no-publish` is enough.

## Severity mapping

- gitleaks: every finding is `critical`.
- NuGet: Critical, High, Moderate to medium, Low.
- semgrep: ERROR to high, WARNING to medium, INFO to low.
- osv-scanner: CVSS score of the vulnerability group (9+ critical, 7+ high, 4+ medium, else low), else the
  database severity.
- grype: Critical, High, Medium, Low; Negligible to low. Unknown from any tool is treated as medium.
- Default gate threshold is `high` (`--fail-on`).

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

This makes `dotnet build` itself fail on vulnerable packages (moderate/high/critical), so the problem appears
before the gate runs.

## CI

```bash
node security-gate/scripts/gate.mjs --root . --fail-on high   # exit 0 pass, 1 fail, 2 incomplete
```

Install the five tools on the runner first, upload `.work/security-gate/` as a build artifact, and treat exit
code 2 as a failed build too.

## Known limits

- Output parsing follows each tool's documented JSON. `node scripts/gate.selftest.mjs` proves the logic with
  fixtures; the first real run of each tool confirms the shape for the installed version. If a tool's output
  changes, the runner reports ERROR for that tool instead of passing.
- osv-scanner/grype can disagree (different databases and matching). The gate reports each separately.
- Reachability is not analysed; a blocking CVE in an unused code path still needs a reasoned suppression.
