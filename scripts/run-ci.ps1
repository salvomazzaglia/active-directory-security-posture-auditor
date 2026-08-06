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
$pesterAvailable = @(Get-Module -ListAvailable -Name Pester | Where-Object {
  $_.Version -ge [version]'5.0.0' -and $_.Version -lt [version]'6.0.0'
} | Sort-Object Version -Descending)
if ($pesterAvailable.Count -gt 0) {
  $pesterModulePath = $pesterAvailable[0].Path
  $testsPath = Join-Path $RepoRoot 'tests'
  $pesterResultPath = Join-Path $RepoRoot 'temp/pester-ci-result.json'
  $pesterDir = Split-Path -Parent $pesterResultPath
  if (-not (Test-Path -LiteralPath $pesterDir)) { New-Item -ItemType Directory -Path $pesterDir -Force | Out-Null }
  # Isolate Pester in a child process so a host-installed Pester 6 assembly cannot conflict.
  $child = @"
`$ErrorActionPreference = 'Stop'
Import-Module -Name '$pesterModulePath' -Force
`$cfg = New-PesterConfiguration
`$cfg.Run.Path = '$testsPath'
`$cfg.Run.PassThru = `$true
`$cfg.Output.Verbosity = 'Normal'
`$p = Invoke-Pester -Configuration `$cfg
[pscustomobject]@{
  TotalCount = `$p.TotalCount
  PassedCount = `$p.PassedCount
  FailedCount = `$p.FailedCount
  SkippedCount = `$p.SkippedCount
  NotRunCount = `$p.NotRunCount
  Version = (Get-Module Pester).Version.ToString()
} | ConvertTo-Json | Set-Content -LiteralPath '$pesterResultPath' -Encoding UTF8
if (`$p.FailedCount -gt 0) { exit 1 } else { exit 0 }
"@
  $childFile = Join-Path $RepoRoot 'temp/pester-ci-child.ps1'
  Set-Content -LiteralPath $childFile -Value $child -Encoding UTF8
  $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
  if ($pwshCmd) { $pwshExe = $pwshCmd.Source } else { $pwshExe = (Get-Command powershell).Source }
  & $pwshExe -NoProfile -File $childFile
  $pesterChildExit = $LASTEXITCODE
  if (Test-Path -LiteralPath $pesterResultPath) {
    $pr = Get-Content -LiteralPath $pesterResultPath -Raw | ConvertFrom-Json
    $pesterTotal = [int]$pr.TotalCount
    $pesterPassed = [int]$pr.PassedCount
    $pesterFailed = [int]$pr.FailedCount
    $pesterSkipped = [int]$pr.SkippedCount
    $pesterNotRun = [int]$pr.NotRunCount
    Write-Host ("Pester={0}" -f $pr.Version)
  }
  if ($pesterChildExit -ne 0 -or $pesterFailed -gt 0) { $failed = $true }
} else {
  Write-Host 'Pester 5.x not installed; skipping' -ForegroundColor Yellow
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
if ($csv -match '(?m)^(=|\+|@)[^,]*,') {
    Write-Host 'CSV formula-injection risk detected' -ForegroundColor Red
    $failed = $true
}
Write-Host ("Strict score={0}" -f $strict.score)
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
