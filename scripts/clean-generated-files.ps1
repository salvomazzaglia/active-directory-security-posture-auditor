#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Apply)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$targets = @('temp','tmp','test-results','local','output','reports','results','exports','live-data','downloads')
foreach ($t in $targets) {
  $p = Join-Path $RepoRoot $t
  if (Test-Path -LiteralPath $p) {
    $item = Get-Item -LiteralPath $p -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Symlinked target rejected: $p" }
    Write-Host "Planned removal: $p"
    if ($Apply -and $PSCmdlet.ShouldProcess($p, 'Remove')) { Remove-Item -LiteralPath $p -Recurse -Force }
  }
}
if (-not $Apply) { Write-Host 'Dry run only. Pass -Apply to remove.' }
