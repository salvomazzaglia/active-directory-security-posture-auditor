#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
$errors = New-Object System.Collections.Generic.List[string]
$cfg = Test-ADSPConfiguration -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -SuppressionsPath (Join-Path $RepoRoot 'config/suppressions.example.json')
if (-not $cfg.valid) { foreach ($e in $cfg.errors) { $errors.Add($e) | Out-Null } }
$rules = @(Get-ADSPRule)
if ($rules.Count -lt 110) { $errors.Add("Rule count $($rules.Count) < 110") | Out-Null }
$html = Get-Content (Join-Path $RepoRoot 'examples/sample-report.html') -Raw -ErrorAction SilentlyContinue
if ($html -and $html -notmatch 'SYNTHETIC DEMONSTRATION DATA') { $errors.Add('Sample HTML missing synthetic marker') | Out-Null }
$deny = @('mimikatz','rubeus','sharphound','secretsdump','Get-LapsADPassword','Invoke-Expression','pull_request_target','self-hosted')
$files = Get-ChildItem $RepoRoot -Recurse -File | Where-Object { $_.FullName -notmatch '\\\.git\\|\\temp\\|\\test-results\\|\\scripts\\_bootstrap' -and $_.Extension -match '\.(ps1|psm1|yml|md|json)$' }
foreach ($f in $files) {
  $t = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
  if (-not $t) { continue }
  foreach ($d in $deny) {
    if ($t -imatch [regex]::Escape($d)) {
      if ($d -eq 'Invoke-Expression' -and $f.Name -match 'validate|guard|test') { continue }
      if ($t -imatch ('forbid|reject|never|must not|do not').* + [regex]::Escape($d)) { continue }
      # allow documentation mentions of prohibited tools as denials
      if ($f.Extension -in '.md','.yml' -and $t -imatch 'never|prohibit|must not|do not') { continue }
    }
  }
  if ($t -imatch 'Set-ADUser|New-ADUser|Remove-ADUser|Add-ADGroupMember|Set-GPRegistryValue|Reset-LapsPassword') {
    if ($f.Name -notmatch 'Tests|guard|SECURITY|CONTRIBUTING|validate') { $errors.Add("Modifying cmdlet reference in $($f.FullName)") | Out-Null }
  }
}
$wf = Get-Content (Join-Path $RepoRoot '.github/workflows/ci.yml') -Raw
if ($wf -match 'self-hosted' -or $wf -match 'pull_request_target') { $errors.Add('Unsafe workflow settings') | Out-Null }
if ($wf -match 'AcknowledgeLiveDirectoryQuery' -or $wf -match ' adsp-audit.ps1 collect') { $errors.Add('Live collect in CI') | Out-Null }
if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Host $_ -ForegroundColor Red }; exit 1 }
Write-Host "Repository validation OK. Rules=$($rules.Count)" -ForegroundColor Green
