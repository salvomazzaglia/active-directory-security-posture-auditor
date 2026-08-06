function Invoke-ADSPEvalTrusts {
    param($Snapshot, $Policy, $Rules)
    if ($null -eq $Policy) { throw 'Policy is required.' }
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'trust' -Message $msg)) | Out-Null
    }
    foreach ($t in @($Snapshot.trusts)) {
        if ($t.direction -eq 'Bidirectional') { AddF 'ADSP-TRU-001' 'Fail' $t.target 'Bidirectional trust requires review.' }
        if ($t.trust_type -eq 'External' -and -not $t.sid_filtering) { AddF 'ADSP-TRU-002' 'Fail' $t.target 'External trust lacks expected SID-filtering/quarantine metadata.' }
        if ($t.trust_type -eq 'Forest' -and (Get-ADSPProp $Policy.thresholds 'require_selective_authentication' $false) -and -not $t.selective_authentication) {
            AddF 'ADSP-TRU-003' 'Fail' $t.target 'Forest trust does not use selective authentication where policy requires it.'
        }
        if ($t.tgt_delegation_enabled) { AddF 'ADSP-TRU-004' 'Fail' $t.target 'TGT delegation enabled across trust.' }
        if ($t.metadata_incomplete -or $t.unresolved) { AddF 'ADSP-TRU-005' 'Fail' $t.target 'Trust target unresolved or metadata incomplete.' }
        if ($t.stale) { AddF 'ADSP-TRU-006' 'Fail' $t.target 'Trust appears stale per operator-defined evidence.' }
        if ($t.direction_unexpected) { AddF 'ADSP-TRU-007' 'Fail' $t.target 'Trust direction differs from policy expectation.' }
        if ($t.transitive -and $t.expands_exposure) { AddF 'ADSP-TRU-008' 'Fail' $t.target 'Transitive trust expands exposure beyond configured expectation.' }
        if ($t.sid_history_risk) { AddF 'ADSP-TRU-009' 'Fail' $t.target 'Trust contains SID-history-related migration risk indicators.' }
        AddF 'ADSP-TRU-010' 'Fail' $t.target 'Trusted-domain information included without querying the remote forest (informational limitation).'
    }
    if (-not $Snapshot.trusts -or @($Snapshot.trusts).Count -eq 0) {
        AddF 'ADSP-TRU-010' 'Pass' 'trusts' 'No trusts in snapshot (or limitation noted elsewhere).'
    }
    return @($out.ToArray())
}

