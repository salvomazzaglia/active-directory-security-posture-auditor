function Invoke-ADSPEvalLaps {
    param($Snapshot, $Policy, $Rules)
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'laps' -Message $msg)) | Out-Null
    }
    $lm = $Snapshot.laps_metadata
    if (-not $lm -or -not $lm.windows_laps_schema_present) { AddF 'ADSP-LAPS-001' 'Fail' 'laps-schema' 'Windows LAPS schema metadata unavailable.' }
    else { AddF 'ADSP-LAPS-001' 'Pass' 'laps-schema' 'Windows LAPS schema metadata present.' }
    if ($lm -and $lm.legacy_laps_schema_present -and -not $lm.windows_laps_schema_present) {
        AddF 'ADSP-LAPS-002' 'Fail' 'laps-schema' 'Only legacy Microsoft LAPS schema indicators present.'
    }
    if ($lm -and $lm.legacy_laps_schema_present -and $lm.windows_laps_schema_present -and $lm.inconsistent_coexistence) {
        AddF 'ADSP-LAPS-011' 'Fail' 'laps-schema' 'Legacy and Windows LAPS metadata coexist inconsistently.'
    }
    foreach ($c in @($Snapshot.computers)) {
        $eligible = [bool](Get-ADSPProp $c 'laps_eligible' $false)
        $exp = Get-ADSPProp $c 'laps_expiration_utc' $null
        $sam = Get-ADSPProp $c 'sam_account_name' ''
        if ($eligible -and -not $exp) { AddF 'ADSP-LAPS-003' 'Fail' $sam 'Eligible computer lacks LAPS expiration metadata.' }
        if (Get-ADSPProp $c 'laps_expiration_overdue' $false) { AddF 'ADSP-LAPS-004' 'Fail' $sam 'LAPS password expiration metadata is overdue.' }
        if (Get-ADSPProp $c 'laps_expiration_far_future' $false) { AddF 'ADSP-LAPS-005' 'Fail' $sam 'LAPS expiration unusually far in the future.' }
    }
    foreach ($p in @($Snapshot.laps_permission_metadata)) {
        if ($p.broad_reader) { AddF 'ADSP-LAPS-006' 'Fail' $p.principal 'Broad principal can read LAPS password attributes (ACL metadata only; password not retrieved).' }
        if ($p.broad_reset) { AddF 'ADSP-LAPS-007' 'Fail' $p.principal 'Broad principal can reset/modify LAPS-related attributes.' }
        if ($p.reader_is_highest_privilege) { AddF 'ADSP-LAPS-008' 'Fail' $p.principal 'LAPS reader includes highest-privilege group; narrower delegation may be preferable.' }
    }
    $hasGpoLaps = $false
    foreach ($g in @($Snapshot.gpo_security_settings)) {
        if ($g.setting_name -match 'LAPS|AdmPwd') { $hasGpoLaps = $true }
    }
    if (-not $hasGpoLaps) {
        AddF 'ADSP-LAPS-009' 'Unavailable' 'laps-policy' 'Windows LAPS encrypted-password policy cannot be verified (GPO metadata absent).'
        AddF 'ADSP-LAPS-010' 'Unavailable' 'laps-dsrm' 'Domain-controller LAPS/DSRM policy cannot be verified.'
    }
    # Blocked attribute presence is a hard failure checked before audit; still emit finding if flag set
    if ($Snapshot.PSObject.Properties['blocked_attribute_detected'] -and $Snapshot.blocked_attribute_detected) {
        AddF 'ADSP-LAPS-012' 'Fail' 'snapshot' 'Snapshot contains a blocked LAPS password attribute.'
    } else {
        AddF 'ADSP-LAPS-012' 'Pass' 'snapshot' 'No blocked LAPS password attributes detected in snapshot.'
    }
    return @($out.ToArray())
}

