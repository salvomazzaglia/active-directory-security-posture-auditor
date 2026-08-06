function Invoke-ADSPEvalServiceAccounts {
    param($Snapshot, $Policy, $Rules)
    if ($null -eq $Policy) { throw 'Policy is required.' }
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'service_account' -Message $msg)) | Out-Null
    }
    $spnMap = @{}
    foreach ($s in @($Snapshot.spns)) {
        $k = [string]$s.spn
        if (-not $spnMap.ContainsKey($k)) { $spnMap[$k] = New-Object System.Collections.Generic.List[string] }
        $spnMap[$k].Add([string]$s.account_sam) | Out-Null
    }
    foreach ($k in $spnMap.Keys) {
        if ($spnMap[$k].Count -gt 1) {
            AddF 'ADSP-SVC-008' 'Fail' $k 'Duplicate SPN exists.'
            AddF 'ADSP-SVC-009' 'Fail' $k 'SPN exists on more than one enabled principal.'
        }
    }
    foreach ($sa in @($Snapshot.service_accounts)) {
        if ($sa.spns -and $sa.password_age_days -gt 90) { AddF 'ADSP-SVC-001' 'Fail' $sa.sam_account_name 'User-based service account has SPN and old password.' }
        if ($sa.password_never_expires) { AddF 'ADSP-SVC-002' 'Fail' $sa.sam_account_name 'Service account password never expires.' }
        if ($sa.is_privileged) { AddF 'ADSP-SVC-003' 'Fail' $sa.sam_account_name 'Service account is privileged.' }
        if ($sa.enabled -and $sa.inactive_days -gt 90) { AddF 'ADSP-SVC-004' 'Fail' $sa.sam_account_name 'Service account inactive but enabled.' }
        if ($sa.trusted_for_delegation) { AddF 'ADSP-SVC-005' 'Fail' $sa.sam_account_name 'Service account configured for unconstrained delegation.' }
        if ($sa.trusted_to_auth_for_delegation) { AddF 'ADSP-SVC-006' 'Fail' $sa.sam_account_name 'Service account configured for protocol transition.' }
        if ($sa.lacks_aes) { AddF 'ADSP-SVC-007' 'Fail' $sa.sam_account_name 'Service account lacks AES support per collected metadata.' }
        if ($sa.credential_clue_detected) { AddF 'ADSP-SVC-014' 'Fail' $sa.object_guid 'Credential clue in descriptive attribute (redacted).' }
        if (-not $sa.owner_label) { AddF 'ADSP-SVC-015' 'Fail' $sa.sam_account_name 'Service account lacks accountable owner label.' }
        if (-not $sa.is_gmsa) { AddF 'ADSP-SVC-013' 'Fail' $sa.sam_account_name 'User service account may be a gMSA migration candidate (advisory).' }
    }
    foreach ($g in @($Snapshot.gmsa_accounts)) {
        if ($g.retrieval_principals_broad) { AddF 'ADSP-SVC-010' 'Fail' $g.sam_account_name 'gMSA retrieval principals include broad privileged/general-purpose group.' }
        if (-not $g.retrieval_principals -or @($g.retrieval_principals).Count -eq 0) { AddF 'ADSP-SVC-011' 'Fail' $g.sam_account_name 'gMSA has no allowed retrieval principal.' }
        if ($g.is_privileged) { AddF 'ADSP-SVC-012' 'Fail' $g.sam_account_name 'gMSA is privileged.' }
    }
    return @($out.ToArray())
}

