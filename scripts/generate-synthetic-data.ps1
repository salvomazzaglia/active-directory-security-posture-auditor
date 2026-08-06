#Requires -Version 5.1
param(
  [string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
# Never imports ActiveDirectory. Never queries host domain.
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
  $OutputDirectory = Join-Path $RepoRoot 'examples/synthetic-snapshot'
}
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
  New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
Remove-Item -LiteralPath (Join-Path $OutputDirectory 'snapshot.json') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $OutputDirectory 'snapshot.manifest.json') -Force -ErrorAction SilentlyContinue
New-ADSPSyntheticSnapshot -OutputDirectory $OutputDirectory | Out-Null
Write-Host ("Synthetic snapshot regenerated at {0}" -f $OutputDirectory) -ForegroundColor Green
