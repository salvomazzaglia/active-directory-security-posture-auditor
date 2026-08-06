#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position=0)][ValidateSet('plan','synthetic','collect','validate','audit','compare','list-rules','explain','report','version')]$Command = 'version',
    [string]$Domain,
    [ValidateSet('Minimal','Standard','Extended')]$CollectionProfile = 'Standard',
    [string]$OutputDirectory,
    [string]$Snapshot,
    [string]$Policy = 'config/baseline.policy.json',
    [string]$Before,
    [string]$After,
    [ValidateSet('Json','Csv','Html','All')]$Format = 'All',
    [ValidateSet('Masked','Hashed','Full')]$PrivacyMode = 'Masked',
    [string]$RuleId,
    [string]$Category,
    [ValidateSet('Critical','High','Medium','Low','Informational')]$Severity,
    [string]$AuditResult,
    [switch]$AcknowledgeLiveDirectoryQuery,
    [switch]$AuthorizedUse,
    [ValidateSet('Informational','Low','Medium','High','Critical')]$FailOn = 'High',
    [int]$MinimumScore = 0,
    [string]$Suppressions,
    [switch]$AllowHashMismatch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force

switch ($Command) {
    'version' { Write-Output (Get-ADSPVersion); exit 0 }
    'plan' {
        if (-not $Domain) { throw '-Domain is required for plan' }
        Get-ADSPCollectionPlan -Domain $Domain -CollectionProfile $CollectionProfile | ConvertTo-Json -Depth 8
        exit 0
    }
    'synthetic' {
        if (-not $OutputDirectory) { $OutputDirectory = Join-Path $RepoRoot 'temp/synthetic' }
        $snap = New-ADSPSyntheticSnapshot -OutputDirectory $OutputDirectory
        Write-Output ("Synthetic snapshot written. Hash={0}" -f $snap.snapshot_hash)
        exit 0
    }
    'collect' {
        Export-ADSPLiveSnapshot -AcknowledgeLiveDirectoryQuery:$AcknowledgeLiveDirectoryQuery -AuthorizedUse:$AuthorizedUse -Domain $Domain -CollectionProfile $CollectionProfile -OutputDirectory $OutputDirectory | Out-Null
        exit 0
    }
    'validate' {
        $pol = Join-Path $RepoRoot $Policy
        $cfg = Test-ADSPConfiguration -PolicyPath $pol
        if ($Snapshot) {
            $snapPath = if ([IO.Path]::IsPathRooted($Snapshot)) { $Snapshot } else { Join-Path $RepoRoot $Snapshot }
            $sv = Test-ADSPSnapshot -SnapshotPath $snapPath -AllowHashMismatch:$AllowHashMismatch
            $cfg = [pscustomobject]@{ valid = ($cfg.valid -and $sv.valid); errors = @($cfg.errors + $sv.errors) }
        }
        $cfg | ConvertTo-Json -Depth 5
        if (-not $cfg.valid) { exit 3 }
        exit 0
    }
    'audit' {
        if (-not $Snapshot) { throw '-Snapshot is required' }
        if (-not $OutputDirectory) { throw '-OutputDirectory is required' }
        $snapPath = if ([IO.Path]::IsPathRooted($Snapshot)) { $Snapshot } else { Join-Path $RepoRoot $Snapshot }
        $polPath = if ([IO.Path]::IsPathRooted($Policy)) { $Policy } else { Join-Path $RepoRoot $Policy }
        $outPath = if ([IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $RepoRoot $OutputDirectory }
        $supPath = $null
        if ($Suppressions) { $supPath = if ([IO.Path]::IsPathRooted($Suppressions)) { $Suppressions } else { Join-Path $RepoRoot $Suppressions } }
        $report = Invoke-ADSPSecurityAudit -SnapshotPath $snapPath -PolicyPath $polPath -OutputDirectory $outPath -Format $Format -PrivacyMode $PrivacyMode -FailOn $FailOn -MinimumScore $MinimumScore -SuppressionsPath $supPath -AllowHashMismatch:$AllowHashMismatch
        Write-Output ("Score={0} Grade={1} Exit={2}" -f $report.score, $report.grade, $report.exit_code)
        exit [int]$report.exit_code
    }
    'compare' {
        if (-not $Before -or -not $After) { throw '-Before and -After are required' }
        if (-not $OutputDirectory) { throw '-OutputDirectory is required' }
        $b = if ([IO.Path]::IsPathRooted($Before)) { $Before } else { Join-Path $RepoRoot $Before }
        $a = if ([IO.Path]::IsPathRooted($After)) { $After } else { Join-Path $RepoRoot $After }
        $polPath = if ([IO.Path]::IsPathRooted($Policy)) { $Policy } else { Join-Path $RepoRoot $Policy }
        $outPath = if ([IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $RepoRoot $OutputDirectory }
        $cmp = Compare-ADSPSnapshot -Before $b -After $a -PolicyPath $polPath -OutputDirectory $outPath -PrivacyMode $PrivacyMode
        Write-Output ("ScoreDelta={0}" -f $cmp.score_delta)
        exit 0
    }
    'list-rules' {
        Get-ADSPRule -Category $Category -Severity $Severity | Select-Object rule_id, title, category, default_severity, enabled | Format-Table -AutoSize
        exit 0
    }
    'explain' {
        if (-not $RuleId) { throw '-RuleId is required' }
        Get-ADSPRuleHelp -RuleId $RuleId | ConvertTo-Json -Depth 6
        exit 0
    }
    'report' {
        if (-not $AuditResult -or -not $OutputDirectory) { throw '-AuditResult and -OutputDirectory are required' }
        $arPath = if ([IO.Path]::IsPathRooted($AuditResult)) { $AuditResult } else { Join-Path $RepoRoot $AuditResult }
        $outPath = if ([IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $RepoRoot $OutputDirectory }
        $ar = Get-Content -LiteralPath $arPath -Raw | ConvertFrom-Json
        Export-ADSPReport -AuditResult $ar -OutputDirectory $outPath -Format $Format -PrivacyMode $PrivacyMode
        exit 0
    }
}
