#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
# Never imports ActiveDirectory. Never queries host domain.
New-ADSPSyntheticSnapshot -OutputDirectory (Join-Path $RepoRoot 'examples/synthetic-snapshot') | Out-Null
Write-Host 'Synthetic snapshot regenerated.' -ForegroundColor Green
