function Invoke-ADSPEvalPrivilegedAccess {
    param($Snapshot, $Policy, $Rules)
    if ($null -eq $Policy) { throw 'Policy is required.' }
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    $th = $Policy.thresholds
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'privileged' -Message $msg)) | Out-Null
    }
    $pm = @($Snapshot.privileged_memberships)
    $highest = @($pm | Where-Object { $_.group_tier -eq 'highest' })
    $directHighest = @($highest | Where-Object { $_.membership_type -eq 'Direct' } | Select-Object -ExpandProperty member_sam -Unique)
    $transHighest = @($highest | Where-Object { $_.membership_type -eq 'Transitive' } | Select-Object -ExpandProperty member_sam -Unique)
    if ($directHighest.Count -gt [int]$th.max_direct_highest_privilege_members) { AddF 'ADSP-PRV-001' 'Fail' 'highest-privilege' "Direct highest-privilege members $($directHighest.Count) exceed expectation." }
    else { AddF 'ADSP-PRV-001' 'Pass' 'highest-privilege' 'Direct highest-privilege membership within expectation.' }
    if ($transHighest.Count -gt [int]$th.max_transitive_highest_privilege_members) { AddF 'ADSP-PRV-002' 'Fail' 'highest-privilege' "Transitive highest-privilege members $($transHighest.Count) exceed expectation." }
    else { AddF 'ADSP-PRV-002' 'Pass' 'highest-privilege' 'Transitive highest-privilege membership within expectation.' }

    foreach ($m in $pm) {
        $u = @($Snapshot.users) | Where-Object { $_.object_guid -eq $m.member_guid -or $_.sam_account_name -eq $m.member_sam } | Select-Object -First 1
        if ($u -and -not $u.enabled) { AddF 'ADSP-PRV-003' 'Fail' $m.member_sam "Disabled account retains privileged membership in $($m.group_sam)." }
        if ($u -and $u.enabled -and $u.inactive_days -gt [int]$th.max_inactive_days) { AddF 'ADSP-PRV-004' 'Fail' $m.member_sam "Inactive privileged account ($($u.inactive_days)d)." }
        if ($u -and $u.account_expired) { AddF 'ADSP-PRV-005' 'Fail' $m.member_sam 'Expired account retains privileged membership.' }
        if ($m.member_class -eq 'service' -or ($u -and $u.is_service_account)) { AddF 'ADSP-PRV-006' 'Fail' $m.member_sam 'Service account is privileged-group member.' }
        if ($m.member_class -eq 'computer') { AddF 'ADSP-PRV-007' 'Fail' $m.member_sam 'Computer account in unexpected privileged group.' }
        if ($m.member_class -eq 'foreignSecurityPrincipal') { AddF 'ADSP-PRV-008' 'Fail' $m.member_sam 'Foreign security principal has privileged membership.' }
        if ($m.unresolved_sid) { AddF 'ADSP-PRV-009' 'Fail' $m.member_sid 'Unresolved SID in privileged membership.' }
        if ($m.path_depth -gt [int]$th.max_membership_nesting_depth) { AddF 'ADSP-PRV-010' 'Fail' $m.member_sam 'Privileged membership path nesting exceeds policy.' }
        if ($m.cycle_detected) { AddF 'ADSP-PRV-011' 'Fail' $m.group_sam 'Privileged group-membership cycle detected.' }
        if ($u -and $u.password_age_days -gt [int]$th.max_privileged_password_age_days -and $m.group_tier -eq 'highest') {
            AddF 'ADSP-PRV-012' 'Fail' $m.member_sam 'Privileged account password age exceeds threshold.'
        }
        if ($u -and $u.password_never_expires -and $m.group_tier -eq 'highest') { AddF 'ADSP-PRV-013' 'Fail' $m.member_sam 'Privileged account password never expires.' }
        if ($u -and $m.group_tier -eq 'highest' -and -not $u.account_not_delegated) { AddF 'ADSP-PRV-014' 'Fail' $m.member_sam 'Privileged account not marked sensitive/cannot be delegated.' }
        if ($u -and $m.group_tier -eq 'highest' -and (Get-ADSPProp $th 'require_protected_users_for_eligible_admins' $false) -and -not (Get-ADSPProp $u 'in_protected_users' $false) -and -not (Get-ADSPProp $u 'is_service_account' $false)) {
            AddF 'ADSP-PRV-015' 'Fail' $m.member_sam 'Eligible privileged account not in Protected Users (policy-driven).'
        }
        if ($u -and (Get-ADSPProp $u 'in_protected_users' $false) -and (Get-ADSPProp $u 'is_service_account' $false)) { AddF 'ADSP-PRV-016' 'Fail' $m.member_sam 'Protected Users contains likely incompatible service account — requires review.' }
        if ($u -and (Get-ADSPProp $u 'spns' $null) -and @((Get-ADSPProp $u 'spns' @())).Count -gt 0 -and $m.group_tier -eq 'highest') { AddF 'ADSP-PRV-017' 'Fail' $m.member_sam 'Privileged account has SPNs.' }
        if ($u -and ((Get-ADSPProp $u 'trusted_for_delegation' $false) -or (Get-ADSPProp $u 'trusted_to_auth_for_delegation' $false)) -and $m.group_tier -eq 'highest') {
            AddF 'ADSP-PRV-018' 'Fail' $m.member_sam 'Privileged account is configured for delegation.'
        }
        if ($u -and (Get-ADSPProp $u 'admin_count' 0) -eq 1 -and -not (Get-ADSPProp $m 'protected_membership' $false)) { AddF 'ADSP-PRV-019' 'Fail' $m.member_sam 'AdminCount inconsistent with protected membership state.' }
    }
    $ops = @($pm | Where-Object { $_.group_tier -eq 'operator' -and $_.membership_type -eq 'Direct' -and $_.member_sam -notin @('Administrator','SYNTHETIC-DEFAULT') })
    if ($ops.Count -gt 0) { AddF 'ADSP-PRV-020' 'Fail' 'operator-groups' 'Built-in operator group contains non-default-looking members (advisory).' }
    else { AddF 'ADSP-PRV-020' 'Pass' 'operator-groups' 'No unexpected operator members detected in snapshot.' }
    $gpoOwners = @($pm | Where-Object { $_.group_sam -match 'Group Policy Creator Owners|GPO-Creator' })
    if ($gpoOwners.Count -gt 1) { AddF 'ADSP-PRV-021' 'Fail' 'gpo-creator-owners' 'Group Policy Creator Owners contains unexpected members.' }
    else { AddF 'ADSP-PRV-021' 'Pass' 'gpo-creator-owners' 'GPO Creator Owners membership within snapshot expectation.' }
    $prewin = @($pm | Where-Object { $_.group_sam -match 'Pre-Windows 2000' })
    if ($prewin.Count -gt 0) { AddF 'ADSP-PRV-022' 'Fail' 'pre-windows-2000' 'Pre-Windows 2000 Compatible Access membership broader than policy.' }
    else { AddF 'ADSP-PRV-022' 'Pass' 'pre-windows-2000' 'No broad Pre-Windows 2000 membership observed.' }
    return @($out.ToArray())
}

