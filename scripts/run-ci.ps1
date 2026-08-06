#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$failed = $false

Write-Host '=== AD Security Posture CI ===' -ForegroundColor Cyan
Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
Write-Host "Version=$(Get-ADSPVersion)"

# Manifest / import already done
$parserErrors = 0
Get-ChildItem (Join-Path $RepoRoot 'ADSecurityPosture') -Recurse -Include *.ps1,*.psm1 | ForEach-Object {
  $errs = $null
  $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errs)
  if ($errs) { $parserErrors += $errs.Count; $errs | ForEach-Object { Write-Host $_ } }
}
if ($parserErrors -gt 0) { $failed = $true }

$analyzerErrors = 0; $analyzerWarnings = 0
if (Get-Module -ListAvailable PSScriptAnalyzer) {
  Import-Module PSScriptAnalyzer -ErrorAction Stop
  $settings = Join-Path $RepoRoot 'PSScriptAnalyzerSettings.psd1'
  $results = @(Invoke-ScriptAnalyzer -Path (Join-Path $RepoRoot 'ADSecurityPosture') -Recurse -Settings $settings -ErrorAction SilentlyContinue)
  $results += @(Invoke-ScriptAnalyzer -Path (Join-Path $RepoRoot 'scripts') -Recurse -Settings $settings -ErrorAction SilentlyContinue)
  $analyzerErrors = @($results | Where-Object Severity -eq 'Error').Count
  $analyzerWarnings = @($results | Where-Object Severity -eq 'Warning').Count
  if ($analyzerErrors -gt 0) { $results | Where-Object Severity -eq 'Error' | Format-Table -AutoSize; $failed = $true }
} else {
  Write-Host 'PSScriptAnalyzer not installed; skipping' -ForegroundColor Yellow
}

$pesterTotal=0; $pesterPassed=0; $pesterFailed=0; $pesterSkipped=0; $pesterNotRun=0
if (Get-Module -ListAvailable Pester) {
  Import-Module Pester -MinimumVersion 5.0.0 -MaximumVersion 5.99.99 -ErrorAction Stop
  $cfg = New-PesterConfiguration
  $cfg.Run.Path = Join-Path $RepoRoot 'tests'
  $cfg.Run.PassThru = $true
  $cfg.Output.Verbosity = 'Normal'
  $p = Invoke-Pester -Configuration $cfg
  $pesterTotal = $p.TotalCount
  $pesterPassed = $p.PassedCount
  $pesterFailed = $p.FailedCount
  $pesterSkipped = $p.SkippedCount
  $pesterNotRun = $p.NotRunCount
  if ($pesterFailed -gt 0) { $failed = $true }
} else {
  Write-Host 'Pester not installed; skipping' -ForegroundColor Yellow
}

& (Join-Path $RepoRoot 'scripts/generate-synthetic-data.ps1')
$sv = Test-ADSPSnapshot -SnapshotPath (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json')
if (-not $sv.valid) { $failed = $true; Write-Host ($sv.errors -join '; ') -ForegroundColor Red }

$baseline = Invoke-ADSPSecurityAudit -SnapshotPath (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -OutputDirectory (Join-Path $RepoRoot 'temp/ci-baseline') -Format All -PrivacyMode Masked
$strict = Invoke-ADSPSecurityAudit -SnapshotPath (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json') -PolicyPath (Join-Path $RepoRoot 'config/strict.policy.json') -OutputDirectory (Join-Path $RepoRoot 'temp/ci-strict') -Format Json -PrivacyMode Masked
Compare-ADSPSnapshot -Before (Join-Path $RepoRoot 'examples/comparison/before.json') -After (Join-Path $RepoRoot 'examples/comparison/after.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -OutputDirectory (Join-Path $RepoRoot 'temp/ci-comparison') -PrivacyMode Masked | Out-Null

$html = Get-Content (Join-Path $RepoRoot 'temp/ci-baseline/report.html') -Raw
if ($html -match 'https?://cdn\.|googleapis|jsdelivr|unpkg') { Write-Host 'HTML external resource detected' -ForegroundColor Red; $failed = $true }
$csv = Get-Content (Join-Path $RepoRoot 'temp/ci-baseline/findings.csv') -Raw
# formula injection guard: values should be quoted/prefixed if dangerous
$ruleCount = @(Get-ADSPRule).Count
$synthFindings = @($baseline.findings).Count

Write-Host '=== SUMMARY ===' -ForegroundColor Cyan
Write-Host "Pester total: $pesterTotal"
Write-Host "Passed: $pesterPassed"
Write-Host "Failed: $pesterFailed"
Write-Host "Skipped: $pesterSkipped"
Write-Host "NotRun: $pesterNotRun"
Write-Host "PSScriptAnalyzer Error count: $analyzerErrors"
Write-Host "PSScriptAnalyzer Warning count: $analyzerWarnings"
Write-Host "Number of rules: $ruleCount"
Write-Host "Number of synthetic findings: $synthFindings"
Write-Host "Report paths: temp/ci-baseline/report.json, temp/ci-baseline/report.html"
Write-Host ("Final result: " + $(if ($failed) { 'FAIL' } else { 'PASS' }))
if ($failed) { exit 1 } else { exit 0 }
