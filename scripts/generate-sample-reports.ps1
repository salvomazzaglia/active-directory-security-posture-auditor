#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
$snap = Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json'
$v = Test-ADSPSnapshot -SnapshotPath $snap
if (-not $v.valid) { throw ($v.errors -join '; ') }
$out = Join-Path $RepoRoot 'temp/sample-gen'
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
$report = Invoke-ADSPSecurityAudit -SnapshotPath $snap -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -OutputDirectory $out -Format All -PrivacyMode Masked
$html = Get-Content (Join-Path $out 'report.html') -Raw
if ($html -notmatch 'SYNTHETIC DEMONSTRATION DATA') { throw 'Synthetic marker missing from HTML' }
$blocked = Get-Content (Join-Path $RepoRoot 'config/sensitive-attributes.json') -Raw | ConvertFrom-Json
foreach ($a in $blocked.blocked_attributes) {
  if ($html -imatch [regex]::Escape($a) + '\s*:') { throw "Blocked attribute leaked: $a" }
}
if ($html -match 'PLACEHOLDER_CREDENTIAL_VALUE|password\s*=\s*\w{4,}') { throw 'Credential-like value present in HTML' }
Copy-Item (Join-Path $out 'report.json') (Join-Path $RepoRoot 'examples/sample-report.json') -Force
Copy-Item (Join-Path $out 'findings.csv') (Join-Path $RepoRoot 'examples/sample-findings.csv') -Force
Copy-Item (Join-Path $out 'privileged-membership.csv') (Join-Path $RepoRoot 'examples/sample-privileged-membership.csv') -Force
Copy-Item (Join-Path $out 'report.html') (Join-Path $RepoRoot 'examples/sample-report.html') -Force
$cmpOut = Join-Path $RepoRoot 'temp/sample-cmp'
Compare-ADSPSnapshot -Before (Join-Path $RepoRoot 'examples/comparison/before.json') -After (Join-Path $RepoRoot 'examples/comparison/after.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -OutputDirectory $cmpOut -PrivacyMode Masked | Out-Null
Copy-Item (Join-Path $cmpOut 'comparison.json') (Join-Path $RepoRoot 'examples/sample-comparison.json') -Force
Write-Host ("Sample reports generated. Score={0} Grade={1}" -f $report.score, $report.grade)
