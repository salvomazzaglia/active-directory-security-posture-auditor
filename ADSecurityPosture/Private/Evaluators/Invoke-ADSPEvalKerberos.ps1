function Invoke-ADSPEvalKerberos {
    param($Snapshot, $Policy, $Rules)
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'kerberos' -Message $msg)) | Out-Null
    }
    $spnMap = @{}
    foreach ($s in @($Snapshot.spns)) {
        $k = [string]$s.spn
        if (-not $spnMap.ContainsKey($k)) { $spnMap[$k] = 0 }
        $spnMap[$k]++
        $acct = @($Snapshot.users + $Snapshot.computers + $Snapshot.service_accounts) | Where-Object { $_.sam_account_name -eq $s.account_sam } | Select-Object -First 1
        if ($acct -and -not (Get-ADSPProp $acct 'enabled' $false)) { AddF 'ADSP-KRB-002' 'Fail' $s.account_sam 'SPN on disabled account.' }
        if ($acct -and (Get-ADSPProp $acct 'inactive_days' 0) -gt 90) { AddF 'ADSP-KRB-003' 'Fail' $s.account_sam 'SPN on inactive account.' }
        if ($acct -and (Get-ADSPProp $acct 'is_privileged' $false)) { AddF 'ADSP-KRB-004' 'Fail' $s.account_sam 'SPN on privileged account.' }
    }
    foreach ($k in $spnMap.Keys) { if ($spnMap[$k] -gt 1) { AddF 'ADSP-KRB-001' 'Fail' $k 'Duplicate SPN.' } }

    foreach ($u in @($Snapshot.users + $Snapshot.service_accounts)) {
        if ((Get-ADSPProp $u 'use_des_key_only' $false)) { AddF 'ADSP-KRB-005' 'Fail' (Get-ADSPProp $u 'sam_account_name') 'DES-only account.' }
        if ((Get-ADSPProp $u 'legacy_encryption_only' $false)) { AddF 'ADSP-KRB-006' 'Fail' (Get-ADSPProp $u 'sam_account_name') 'RC4/legacy-only encryption metadata.' }
        if ((Get-ADSPProp $u 'does_not_require_preauth' $false)) { AddF 'ADSP-KRB-007' 'Fail' (Get-ADSPProp $u 'sam_account_name') 'Kerberos preauthentication disabled.' }
        if (-not (Get-ADSPProp $u 'account_not_delegated' $false) -and (Get-ADSPProp $u 'is_privileged' $false)) { AddF 'ADSP-KRB-013' 'Fail' (Get-ADSPProp $u 'sam_account_name') 'Privileged account is delegable.' }
        if (-not (Get-ADSPProp $u 'account_not_delegated' $false) -and (Get-ADSPProp $u 'is_service_account' $false)) { AddF 'ADSP-KRB-014' 'Fail' (Get-ADSPProp $u 'sam_account_name') 'Sensitive service account is delegable.' }
        if ((Get-ADSPProp $u 'in_protected_users' $false) -and (Get-ADSPProp $u 'lacks_aes' $false)) { AddF 'ADSP-KRB-017' 'Fail' (Get-ADSPProp $u 'sam_account_name') 'Protected Users member lacks AES-compatible evidence.' }
        if ((Get-ADSPProp $u 'sam_account_name') -eq 'krbtgt' -and (Get-ADSPProp $u 'password_age_days' 0) -gt [int]$Policy.thresholds.max_krbtgt_password_age_days) {
            AddF 'ADSP-KRB-018' 'Fail' (Get-ADSPProp $u 'sam_account_name') 'krbtgt password age exceeds threshold.'
        }
    }
    $krbLike = @($Snapshot.users | Where-Object { $_.sam_account_name -like 'krbtgt*' })
    if ($krbLike.Count -gt 1) { AddF 'ADSP-KRB-019' 'Fail' 'krbtgt' 'Multiple krbtgt-like objects require review.' }

    foreach ($d in @($Snapshot.delegation_metadata)) {
        $isDc = [bool]$d.is_domain_controller
        if ($d.unconstrained -and -not $isDc) { AddF 'ADSP-KRB-008' 'Fail' $d.account_sam 'Unconstrained delegation on non-DC account.' }
        if ($d.unconstrained -and $d.sensitive) { AddF 'ADSP-KRB-009' 'Fail' $d.account_sam 'Unconstrained delegation on sensitive account.' }
        if ($d.constrained_high_impact) { AddF 'ADSP-KRB-010' 'Fail' $d.account_sam 'Constrained delegation targets high-impact service classes.' }
        if ($d.protocol_transition) { AddF 'ADSP-KRB-011' 'Fail' $d.account_sam 'Protocol transition enabled.' }
        if ($d.rbcd_broad) { AddF 'ADSP-KRB-012' 'Fail' $d.account_sam 'RBCD grants access to unexpected/broad principal.' }
        if ($d.unresolved_target) { AddF 'ADSP-KRB-021' 'Fail' $d.account_sam 'Delegation target references unresolved SPN.' }
        if ($d.high_privilege_broad_scope) { AddF 'ADSP-KRB-022' 'Fail' $d.account_sam 'Delegation combines high privilege and broad service scope.' }
    }
    if (-not $Snapshot.authentication_policies -or @($Snapshot.authentication_policies).Count -eq 0) {
        AddF 'ADSP-KRB-015' 'Fail' 'auth-policy' 'Authentication policy absent for configured sensitive classes (informational/strict).'
    }
    foreach ($silo in @($Snapshot.authentication_policy_silos)) {
        if ($silo.inconsistent_membership) { AddF 'ADSP-KRB-016' 'Fail' $silo.name 'Authentication-policy silo membership inconsistent.' }
    }
    if (-not $Snapshot.kerberos_metadata) { AddF 'ADSP-KRB-020' 'Unavailable' 'kerberos-policy' 'Kerberos policy setting unavailable from snapshot.' }
    else { AddF 'ADSP-KRB-020' 'Pass' 'kerberos-policy' 'Kerberos metadata present.' }
    return @($out.ToArray())
}


