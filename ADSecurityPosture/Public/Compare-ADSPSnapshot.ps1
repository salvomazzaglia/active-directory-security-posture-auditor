function Compare-ADSPSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Before,
        [Parameter(Mandatory)][string]$After,
        [string]$PolicyPath = (Join-Path $script:ADSPRepoRoot 'config/baseline.policy.json'),
        [string]$OutputDirectory,
        [ValidateSet('Masked','Hashed','Full')]$PrivacyMode = 'Masked'
    )
    $beforeReport = Invoke-ADSPSecurityAudit -SnapshotPath $Before -PolicyPath $PolicyPath -PrivacyMode $PrivacyMode -FailOn Critical -MinimumScore 0
    $afterReport = Invoke-ADSPSecurityAudit -SnapshotPath $After -PolicyPath $PolicyPath -PrivacyMode $PrivacyMode -FailOn Critical -MinimumScore 0
    $beforeSnap = Import-ADSPSnapshotInternal -Path $Before
    $afterSnap = Import-ADSPSnapshotInternal -Path $After

    function KeyF($f) { "{0}|{1}" -f $f.rule_id, $f.target_id }
    $beforeMap = @{}; foreach ($f in $beforeReport.findings) { $beforeMap[(KeyF $f)] = $f }
    $afterMap = @{}; foreach ($f in $afterReport.findings) { $afterMap[(KeyF $f)] = $f }
    $new = @(); $resolved = @(); $unchanged = @(); $sevChanged = @()
    foreach ($k in $afterMap.Keys) {
        if (-not $beforeMap.ContainsKey($k)) { $new += $afterMap[$k] }
        elseif ($beforeMap[$k].severity -ne $afterMap[$k].severity) { $sevChanged += @{ before=$beforeMap[$k]; after=$afterMap[$k] } }
        else { $unchanged += $afterMap[$k] }
    }
    foreach ($k in $beforeMap.Keys) {
        if (-not $afterMap.ContainsKey($k)) {
            $incomplete = $afterReport.snapshot_completeness -ne 'Complete'
            $resolved += [pscustomobject]@{ finding=$beforeMap[$k]; remediation_claimed=(-not $incomplete); note=$(if($incomplete){'Second snapshot incomplete; do not claim remediation.'}else{'Finding absent in after snapshot.'}) }
        }
    }
    $comparison = [pscustomobject]@{
        tool_name='active-directory-security-posture-auditor'
        tool_version='1.0.0'
        generated_at_utc=[datetime]::UtcNow.ToString('o')
        synthetic = ([bool]$beforeSnap.synthetic -and [bool]$afterSnap.synthetic)
        privacy_mode=$PrivacyMode
        score_before=$beforeReport.score
        score_after=$afterReport.score
        score_delta=([int]$afterReport.score - [int]$beforeReport.score)
        grade_before=$beforeReport.grade
        grade_after=$afterReport.grade
        new_findings=$new
        resolved_findings=$resolved
        unchanged_findings=$unchanged
        severity_changes=$sevChanged
        privileged_members_added = @()
        privileged_members_removed = @()
        limitations=@('Comparison reflects snapshot contents only. Removed findings do not prove remediation if collectors were incomplete.')
        marker='SYNTHETIC DEMONSTRATION DATA'
    }
    # privileged membership drift
    $bPriv = @($beforeSnap.privileged_memberships | ForEach-Object { "{0}|{1}" -f $_.group_sam, $_.member_sam })
    $aPriv = @($afterSnap.privileged_memberships | ForEach-Object { "{0}|{1}" -f $_.group_sam, $_.member_sam })
    $comparison.privileged_members_added = @($aPriv | Where-Object { $_ -notin $bPriv })
    $comparison.privileged_members_removed = @($bPriv | Where-Object { $_ -notin $aPriv })

    if ($OutputDirectory) {
        $out = Assert-ADSPSafePath -Path $OutputDirectory -IsOutput -AllowAbsolute -AllowOverwrite
        if (-not (Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }
        New-ADSPJsonReport -Report $comparison -Path (Join-Path $out 'comparison.json')
    }
    return $comparison
}
