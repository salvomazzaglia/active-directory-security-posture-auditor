function Invoke-ADSPEvalAccountSecurity {
    param($Snapshot, $Policy, $Rules)
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    $th = $Policy.thresholds
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'user' -Message $msg)) | Out-Null
    }
    $upns = @{}
    foreach ($u in @($Snapshot.users)) {
        if ($u.password_not_required) { AddF 'ADSP-ACC-001' 'Fail' $u.sam_account_name 'PasswordNotRequired enabled.' }
        if ($u.password_never_expires -and -not $u.is_service_account) { AddF 'ADSP-ACC-002' 'Fail' $u.sam_account_name 'PasswordNeverExpires outside approved service-account policy.' }
        if ($u.reversible_encryption) { AddF 'ADSP-ACC-003' 'Fail' $u.sam_account_name 'Reversible password encryption enabled.' }
        if ($u.does_not_require_preauth) { AddF 'ADSP-ACC-004' 'Fail' $u.sam_account_name 'Kerberos preauthentication not required.' }
        if ($u.use_des_key_only) { AddF 'ADSP-ACC-005' 'Fail' $u.sam_account_name 'DES-only Kerberos flag enabled.' }
        if ($u.legacy_encryption_only) { AddF 'ADSP-ACC-006' 'Fail' $u.sam_account_name 'Account explicitly supports only legacy Kerberos encryption metadata.' }
        if ($u.sid_history -and @($u.sid_history).Count -gt 0) { AddF 'ADSP-ACC-007' 'Fail' $u.sam_account_name 'SIDHistory present — requires migration context review.' }
        if ($u.enabled -and $u.inactive_days -gt [int]$th.max_inactive_days) { AddF 'ADSP-ACC-008' 'Fail' $u.sam_account_name 'Enabled account inactive beyond threshold.' }
        if ($u.enabled -and $u.never_logged_on -and $u.age_days -gt [int]$th.max_inactive_days) { AddF 'ADSP-ACC-009' 'Fail' $u.sam_account_name 'Enabled account never logged on beyond creation-age threshold.' }
        if (-not $u.enabled -and $u.in_sensitive_group) { AddF 'ADSP-ACC-010' 'Fail' $u.sam_account_name 'Disabled account remains in security-sensitive groups.' }
        if ($u.account_expired -and $u.enabled) { AddF 'ADSP-ACC-011' 'Fail' $u.sam_account_name 'Expired account remains enabled.' }
        if ($u.password_age_days -gt [int]$th.max_password_age_days) { AddF 'ADSP-ACC-012' 'Fail' $u.sam_account_name 'Password age exceeds policy.' }
        if ($u.cannot_change_password -and -not $u.is_service_account) { AddF 'ADSP-ACC-013' 'Fail' $u.sam_account_name 'Account cannot change password unexpectedly.' }
        if ([string]::IsNullOrWhiteSpace($u.user_principal_name) -and $u.object_class -eq 'user') { AddF 'ADSP-ACC-014' 'Fail' $u.sam_account_name 'UPN missing.' }
        if ($u.user_principal_name) {
            if ($upns.ContainsKey($u.user_principal_name)) { AddF 'ADSP-ACC-015' 'Fail' $u.sam_account_name 'Duplicate UPN detected.' }
            else { $upns[$u.user_principal_name] = $true }
        }
        if ($u.credential_clue_detected) { AddF 'ADSP-ACC-016' 'Fail' $u.object_guid 'Allowlisted descriptive attribute contains a credential-like clue. Matched value is redacted.' }
        if ($u.description_admin_heuristic) { AddF 'ADSP-ACC-017' 'Fail' $u.sam_account_name 'Broad/generic administrative description heuristic matched.' }
        if ($u.naming_suggests_temporary -and -not $u.account_expires) { AddF 'ADSP-ACC-018' 'Fail' $u.sam_account_name 'Temporary/vendor-like account lacks expiration.' }
        if ($u.spns -and @($u.spns).Count -gt 0 -and -not $u.is_service_account) { AddF 'ADSP-ACC-019' 'Fail' $u.sam_account_name 'Account has SPN but is not classified as approved service account.' }
        if ($u.no_modern_kerberos_etypes) { AddF 'ADSP-ACC-020' 'Fail' $u.sam_account_name 'No clearly usable modern Kerberos encryption type in collected metadata.' }
    }
    return @($out.ToArray())
}

