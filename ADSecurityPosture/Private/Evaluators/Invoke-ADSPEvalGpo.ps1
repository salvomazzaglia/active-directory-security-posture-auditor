function Invoke-ADSPEvalGpo {
    param($Snapshot, $Policy, $Rules)
    if ($null -eq $Policy) { throw 'Policy is required.' }
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'gpo' -Message $msg)) | Out-Null
    }
    $settings = @($Snapshot.gpo_security_settings)
    if ($settings.Count -eq 0) {
        foreach ($id in @('ADSP-GPO-001','ADSP-GPO-002','ADSP-GPO-003','ADSP-GPO-004','ADSP-GPO-005','ADSP-GPO-006','ADSP-GPO-007','ADSP-GPO-008','ADSP-GPO-009','ADSP-GPO-010','ADSP-GPO-011','ADSP-GPO-012','ADSP-GPO-019')) {
            AddF $id 'Unavailable' 'gpo' 'GPO security setting not present in snapshot; effective policy cannot be inferred.'
        }
    } else {
        function GetSetting($name) { @($settings | Where-Object { $_.setting_name -eq $name } | Select-Object -First 1) }
        $ldap = GetSetting 'LDAPServerSigning'
        if ($ldap -and [string]$ldap.value -ne 'Require signing') { AddF 'ADSP-GPO-001' 'Fail' $ldap.gpo_name 'DC LDAP signing not set to configured secure value.' }
        elseif ($ldap) { AddF 'ADSP-GPO-001' 'Pass' $ldap.gpo_name 'LDAP server signing meets policy representation.' }
        $client = GetSetting 'LDAPClientSigning'
        if ($client -and [string]$client.value -eq 'None') { AddF 'ADSP-GPO-002' 'Fail' $client.gpo_name 'LDAP client signing below policy.' }
        $cb = GetSetting 'LDAPChannelBinding'
        if (-not $cb -or [string]$cb.value -match 'Never|None') {
            if (Get-ADSPProp $Policy.thresholds 'require_channel_binding' $false) { AddF 'ADSP-GPO-003' 'Fail' 'ldap-channel-binding' 'LDAP channel-binding absent or below policy.' }
            else { AddF 'ADSP-GPO-003' 'Fail' 'ldap-channel-binding' 'LDAP channel-binding absent or below policy (contextual).' }
        }
        $lm = GetSetting 'LmCompatibilityLevel'
        if ($lm -and [int]$lm.value -lt 3) { AddF 'ADSP-GPO-004' 'Fail' $lm.gpo_name 'LAN Manager authentication level permits legacy behavior.' }
        $lmhash = GetSetting 'NoLMHash'
        if ($lmhash -and [string]$lmhash.value -ne '1') { AddF 'ADSP-GPO-005' 'Fail' $lmhash.gpo_name 'LM hash storage not disabled where represented.' }
        $anon = GetSetting 'AnonymousSidTranslation'
        if ($anon -and [string]$anon.value -eq 'Enabled') { AddF 'ADSP-GPO-006' 'Fail' $anon.gpo_name 'Anonymous SID/name translation enabled.' }
        $sc = GetSetting 'RequireSignOrSeal'
        if ($sc -and [string]$sc.value -ne 'Enabled') { AddF 'ADSP-GPO-007' 'Fail' $sc.gpo_name 'Secure-channel signing/encryption requirement below policy.' }
        foreach ($pair in @(
            @('ADSP-GPO-008','AuditAccountManage'),
            @('ADSP-GPO-009','AuditDSChanges'),
            @('ADSP-GPO-010','AuditKerberos'),
            @('ADSP-GPO-011','AuditLogon')
        )) {
            $s = GetSetting $pair[1]
            if (-not $s) { AddF $pair[0] 'Unavailable' $pair[1] 'Auditing setting absent or unavailable.' }
        }
        $adv = GetSetting 'AuditSubcategoryOverride'
        if (-not $adv -or [string]$adv.value -ne 'Enabled') { AddF 'ADSP-GPO-012' 'Fail' 'audit-override' 'Advanced audit-policy subcategory override not configured.' }
        $minPwdLenSetting = GetSetting 'MinimumPasswordLength'
        if ($minPwdLenSetting -and [int]$minPwdLenSetting.value -lt [int]$Policy.thresholds.min_password_length) { AddF 'ADSP-GPO-013' 'Fail' $minPwdLenSetting.gpo_name 'Default domain password policy below policy.' }
        $lock = GetSetting 'LockoutThreshold'
        if ($lock -and ([int]$lock.value -le 0)) { AddF 'ADSP-GPO-014' 'Fail' $lock.gpo_name 'Default domain lockout policy below policy.' }
        $tgt = GetSetting 'MaxTicketAge'
        if ($tgt -and ([int]$tgt.value -gt 10 -or [int]$tgt.value -lt 1)) { AddF 'ADSP-GPO-015' 'Fail' $tgt.gpo_name 'Kerberos ticket policy outside configured thresholds.' }
        AddF 'ADSP-GPO-019' 'Fail' 'gpo' 'GPO report exists but effective application cannot be determined (precedence/filtering uncertainty).'
    }
    foreach ($g in @($Snapshot.gpo_metadata)) {
        if ($g.unexpected_owner -or $g.unresolved_owner) { AddF 'ADSP-GPO-016' 'Fail' $g.display_name 'GPO has unexpected or unresolved owner.' }
        if ($g.broad_edit_rights) { AddF 'ADSP-GPO-017' 'Fail' $g.display_name 'GPO grants edit rights to a broad principal.' }
        if ($g.security_relevant -and -not $g.linked) { AddF 'ADSP-GPO-018' 'Fail' $g.display_name 'Security-relevant GPO is unlinked (informational).' }
    }
    $trunc = @($Snapshot.collectors | Where-Object { $_.collector_id -match 'gpo' -and ($_.truncated -or $_.status -eq 'Partial') })
    if ($trunc.Count -gt 0) { AddF 'ADSP-GPO-020' 'Fail' 'gpo' 'GPO collection truncated or incomplete.' }
    else { AddF 'ADSP-GPO-020' 'Pass' 'gpo' 'GPO collectors not marked truncated.' }
    return @($out.ToArray())
}

