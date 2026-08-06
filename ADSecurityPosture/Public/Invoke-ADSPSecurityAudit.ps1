function Invoke-ADSPSecurityAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [string]$PolicyPath = (Join-Path $script:ADSPRepoRoot 'config/baseline.policy.json'),
        [string]$SuppressionsPath,
        [string]$OutputDirectory,
        [ValidateSet('Json','Csv','Html','All')]$Format = 'All',
        [ValidateSet('Masked','Hashed','Full')]$PrivacyMode = 'Masked',
        [ValidateSet('Informational','Low','Medium','High','Critical')]$FailOn = 'High',
        [int]$MinimumScore = 0,
        [switch]$AllowHashMismatch,
        [string]$PrivacySalt
    )
    $validation = Test-ADSPSnapshot -SnapshotPath $SnapshotPath -AllowHashMismatch:$AllowHashMismatch
    if (-not $validation.valid -and -not $AllowHashMismatch) {
        throw ("Snapshot validation failed: " + ($validation.errors -join '; '))
    }
    $snap = Import-ADSPSnapshotInternal -Path $SnapshotPath
    $hashStatus = 'Verified'
    $expected = Get-ADSPSnapshotHash -Snapshot $snap
    if ([string]$snap.snapshot_hash -ne $expected) {
        if ($AllowHashMismatch) { $hashStatus = 'Untrusted' } else { $hashStatus = 'Mismatch' }
    }
    $policy = Resolve-ADSPPolicy -PolicyPath $PolicyPath
    $suppressions = @()
    if ($SuppressionsPath) {
        $sup = Get-Content -LiteralPath (Assert-ADSPSafePath -Path $SuppressionsPath -AllowAbsolute -MustExist) -Raw | ConvertFrom-Json
        $suppressions = @($sup.suppressions)
    }
    $findings = @(Invoke-ADSPRuleEngine -Snapshot $snap -Policy $policy -Suppressions $suppressions)
    $scoreInfo = Get-ADSPScore -Findings $findings -Policy $policy

    $sevCounts = [ordered]@{ Critical=0; High=0; Medium=0; Low=0; Informational=0 }
    $catCounts = @{}
    $resultCounts = @{}
    foreach ($f in $findings) {
        if ($sevCounts.Contains($f.severity)) { $sevCounts[$f.severity] = [int]$sevCounts[$f.severity] + 1 }
        if (-not $catCounts.ContainsKey($f.category)) { $catCounts[$f.category] = 0 }
        $catCounts[$f.category]++
        if (-not $resultCounts.ContainsKey($f.result)) { $resultCounts[$f.result] = 0 }
        $resultCounts[$f.result]++
    }

    $completeness = 'Complete'
    if (@($snap.collectors | Where-Object { $_.status -in @('Partial','Unavailable','Error') }).Count -gt 0) { $completeness = 'Partial' }

    # privacy transform for report findings targets
    $alias = @{}
    if ($PrivacyMode -eq 'Full') {
        Write-ADSPConsole -Level Warn -Message 'Full privacy mode selected. Reports may contain sensitive identity metadata. Never includes passwords/hashes/LAPS/gMSA secrets.'
    }
    $privacyFindings = foreach ($f in $findings) {
        $copy = $f | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        if ($PrivacyMode -ne 'Full') {
            $copy.target_id = ConvertTo-ADSPPrivacyValue -Value $copy.target_id -PrivacyMode $PrivacyMode -Kind 'generic' -AliasMap $alias -Salt $PrivacySalt
        }
        if ($copy.message -match 'credential-like clue') {
            $copy.message = 'Allowlisted descriptive attribute contains a credential-like clue. Matched value is redacted.'
        }
        $copy
    }

    $report = [pscustomobject]@{
        tool_name = 'active-directory-security-posture-auditor'
        tool_version = '1.0.0'
        schema_version = '1.0.0'
        generated_at_utc = [datetime]::UtcNow.ToString('o')
        synthetic = [bool]$snap.synthetic
        snapshot_id = $snap.snapshot_id
        snapshot_hash_status = $hashStatus
        source_mode = $snap.source_mode
        policy = $policy.policy_id
        privacy_mode = $PrivacyMode
        domain_summary = $snap.target_domain_label
        forest_summary = $snap.target_forest_label
        collector_status_counts = $snap.collector_status_counts
        snapshot_completeness = $completeness
        object_counts = @{
            users = @($snap.users).Count
            groups = @($snap.groups).Count
            computers = @($snap.computers).Count
            trusts = @($snap.trusts).Count
        }
        privileged_access_summary = @{
            memberships = @($snap.privileged_memberships | Select-Object group_sam, member_sam, membership_type, path_depth)
            direct_highest = @($snap.privileged_memberships | Where-Object { $_.group_tier -eq 'highest' -and $_.membership_type -eq 'Direct' }).Count
            transitive_highest = @($snap.privileged_memberships | Where-Object { $_.group_tier -eq 'highest' -and $_.membership_type -eq 'Transitive' }).Count
        }
        account_summary = @{ enabled = @($snap.users | Where-Object enabled).Count; disabled = @($snap.users | Where-Object { -not $_.enabled }).Count }
        kerberos_summary = @{ spn_count = @($snap.spns).Count }
        delegation_summary = @{ entries = @($snap.delegation_metadata).Count }
        service_account_summary = @{ count = @($snap.service_accounts).Count; gmsa = @($snap.gmsa_accounts).Count }
        computer_summary = @{ count = @($snap.computers).Count; dcs = @($snap.domain_controllers).Count }
        laps_summary = @{ schema = [bool]$snap.laps_metadata.windows_laps_schema_present }
        trust_summary = @{ count = @($snap.trusts).Count }
        gpo_summary = @{ count = @($snap.gpo_metadata).Count }
        acl_summary = @{ count = @($snap.critical_object_acls).Count }
        result_counts = $resultCounts
        severity_counts = $sevCounts
        category_counts = $catCounts
        score = $scoreInfo.score
        grade = $scoreInfo.grade
        score_explanation = $scoreInfo.explanation
        highest_severity = (@($findings | Where-Object { -not $_.suppressed } | Sort-Object @{Expression={@{'Critical'=4;'High'=3;'Medium'=2;'Low'=1;'Informational'=0}[$_.severity]};Descending=$true} | Select-Object -First 1)).severity
        findings = @($privacyFindings)
        suppressions = $suppressions
        unavailable_checks = @($findings | Where-Object { $_.result -eq 'Unavailable' } | Select-Object rule_id, message)
        collection_limitations = @($snap.limitations)
        recommendations = @(
            'Review Critical and High policy-driven findings with directory owners.',
            'Treat the posture score as a prioritization aid, not certification.',
            'Protect raw snapshots; they can contain sensitive identity metadata.'
        )
        security_notice = 'This project is not Microsoft Defender for Identity. It does not provide behavioral detection, monitor authentication traffic, inspect endpoint memory, retrieve password hashes, retrieve LAPS passwords, or retrieve gMSA managed-password blobs. An offline snapshot can become stale immediately after collection. Some findings are intentionally contextual and require operational review.'
        exit_code = 0
        internal_error = $false
        score_deductions = $scoreInfo.deductions
    }
    $report.exit_code = Get-ADSPExitCode -Report $report -FailOn $FailOn -MinimumScore $MinimumScore

    if ($OutputDirectory) {
        $out = Assert-ADSPSafePath -Path $OutputDirectory -IsOutput -AllowAbsolute -AllowOverwrite
        if (-not (Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }
        Export-ADSPReport -AuditResult $report -OutputDirectory $out -Format $Format -PrivacyMode $PrivacyMode
    }
    return $report
}
