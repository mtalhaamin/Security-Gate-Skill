<#
.SYNOPSIS
  Installs the scanners the Security Gate needs into ./tools (nothing is installed system-wide).

.DESCRIPTION
  Downloads the latest official Windows release of gitleaks, osv-scanner and grype from GitHub, verifies the
  SHA256 checksum published with each release, and puts the executables in tools/bin. Semgrep is installed into
  its own Python virtual environment (tools/semgrep-venv). NuGet audit needs only the .NET SDK (not installed here).

  Run from the repository root:   powershell -ExecutionPolicy Bypass -File .\install-tools.ps1

.PARAMETER ToolsDir     Target folder (default: ./tools next to this script).
.PARAMETER SkipSemgrep  Do not create the semgrep virtual environment.
.PARAMETER Force        Re-download even if the tool is already present.
#>
[CmdletBinding()]
param(
  [string]$ToolsDir = (Join-Path $PSScriptRoot 'tools'),
  [switch]$SkipSemgrep,
  [switch]$Force
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$headers = @{ 'User-Agent' = 'security-gate-installer' }
$bin = Join-Path $ToolsDir 'bin'
$dl = Join-Path $ToolsDir '_downloads'
New-Item -ItemType Directory -Force $bin, $dl | Out-Null

$tools = @(
  @{ Name = 'gitleaks';    Repo = 'gitleaks/gitleaks';    Exe = 'gitleaks.exe';    Asset = '^gitleaks_.*_windows_x64\.zip$';     Sums = '^gitleaks_.*_checksums\.txt$' },
  @{ Name = 'osv-scanner'; Repo = 'google/osv-scanner';   Exe = 'osv-scanner.exe'; Asset = '^osv-scanner_windows_amd64\.exe$';  Sums = '^osv-scanner_SHA256SUMS$' },
  @{ Name = 'grype';       Repo = 'anchore/grype';        Exe = 'grype.exe';       Asset = '^grype_.*_windows_amd64\.zip$';      Sums = '^grype_.*_checksums\.txt$' }
)

foreach ($t in $tools) {
  $target = Join-Path $bin $t.Exe
  if ((Test-Path $target) -and -not $Force) { Write-Host "$($t.Name): already present, skipping (use -Force to re-download)"; continue }
  Write-Host "$($t.Name): looking up latest release ..."
  $rel = Invoke-RestMethod "https://api.github.com/repos/$($t.Repo)/releases/latest" -Headers $headers
  $asset = $rel.assets | Where-Object { $_.name -match $t.Asset } | Select-Object -First 1
  $sums = $rel.assets | Where-Object { $_.name -match $t.Sums } | Select-Object -First 1
  if (-not $asset -or -not $sums) { throw "$($t.Name): expected release assets not found in $($rel.tag_name)" }

  $file = Join-Path $dl $asset.name
  Invoke-WebRequest $asset.browser_download_url -OutFile $file -UseBasicParsing -Headers $headers
  $sumsFile = Join-Path $dl ($asset.name + '.sums.txt')
  Invoke-WebRequest $sums.browser_download_url -OutFile $sumsFile -UseBasicParsing -Headers $headers

  $line = Select-String -Path $sumsFile -Pattern ([regex]::Escape($asset.name)) | Select-Object -First 1
  if (-not $line) { throw "$($t.Name): no checksum line for $($asset.name)" }
  $expected = ($line.Line -split '\s+')[0].ToLower()
  $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { Remove-Item $file -Force; throw "$($t.Name): CHECKSUM MISMATCH (expected $expected, got $actual). Nothing was installed." }
  Write-Host "$($t.Name) $($rel.tag_name): SHA256 verified"

  if ($asset.name -like '*.zip') {
    $x = Join-Path $dl ('x_' + $t.Name)
    if (Test-Path $x) { Remove-Item $x -Recurse -Force }
    Expand-Archive $file -DestinationPath $x -Force
    Copy-Item (Join-Path $x $t.Exe) $target -Force
  } else {
    Copy-Item $file $target -Force
  }
}

if (-not $SkipSemgrep) {
  $venv = Join-Path $ToolsDir 'semgrep-venv'
  $semgrep = Join-Path $venv 'Scripts\semgrep.exe'
  if ((Test-Path $semgrep) -and -not $Force) { Write-Host 'semgrep: already present, skipping' }
  else {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'semgrep needs Python 3 on PATH (https://www.python.org/downloads/). Re-run with -SkipSemgrep to skip it.' }
    Write-Host 'semgrep: creating virtual environment and installing (a few minutes) ...'
    python -m venv $venv
    & (Join-Path $venv 'Scripts\python.exe') -m pip install --disable-pip-version-check --quiet semgrep
    if ($LASTEXITCODE -ne 0) { throw 'pip install semgrep failed' }
  }
}

Write-Host "`nInstalled in $ToolsDir :"
& (Join-Path $bin 'gitleaks.exe') version
(& (Join-Path $bin 'osv-scanner.exe') --version | Select-Object -First 1)
(& (Join-Path $bin 'grype.exe') version | Select-Object -First 2)
$sg = Join-Path $ToolsDir 'semgrep-venv\Scripts\semgrep.exe'
if (Test-Path $sg) { "semgrep $(& $sg --version)" }
Write-Host "`nNext: node security-gate/scripts/gate.mjs --preflight"
