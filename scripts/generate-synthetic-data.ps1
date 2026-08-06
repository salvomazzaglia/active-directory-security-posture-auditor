#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
# Never imports ActiveDirectory. Never queries host domain.
$out = Join-Path $RepoRoot 'examples/synthetic-snapshot'
if (-not (Test-Path -LiteralPath $out)) {
  New-Item -ItemType Directory -Path $out -Force | Out-Null
}
Remove-Item -LiteralPath (Join-Path $out 'snapshot.json') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $out 'snapshot.manifest.json') -Force -ErrorAction SilentlyContinue
New-ADSPSyntheticSnapshot -OutputDirectory $out | Out-Null
Write-Host 'Synthetic snapshot regenerated.' -ForegroundColor Green
