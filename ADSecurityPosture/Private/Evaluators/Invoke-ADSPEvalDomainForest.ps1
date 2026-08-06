function Invoke-ADSPEvalDomainForest {
    param($Snapshot, $Policy, $Rules)
    if ($null -eq $Policy) { throw 'Policy is required.' }
    $out = New-Object System.Collections.Generic.List[object]
    $th = $Policy.thresholds
    $ruleMap = @{}
    foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }

    function AddF($id, $result, $target, $msg, $evidence = @{}) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'domain' -Message $msg -Evidence $evidence)) | Out-Null
    }

    $domain = @($Snapshot.domains) | Select-Object -First 1
    $forest = $Snapshot.forest
    $pp = @($Snapshot.password_policies) | Select-Object -First 1

    if ($ruleMap.ContainsKey('ADSP-DOM-015')) {
        if ([string]$Snapshot.schema_version -ne '1.0.0') {
            AddF 'ADSP-DOM-015' 'Fail' 'snapshot' "Unsupported schema_version '$($Snapshot.schema_version)'."
        } else {
            AddF 'ADSP-DOM-015' 'Pass' 'snapshot' 'Schema version supported.'
        }
    }

    if ($domain -and $th.min_domain_functional_level) {
        $levels = @('Windows2008Domain','Windows2008R2Domain','Windows2012Domain','Windows2012R2Domain','Windows2016Domain','Windows2019Domain','Windows2022Domain','Windows2025Domain')
        $cur = [string]$domain.functional_level
        $min = [string]$th.min_domain_functional_level
        $ci = [array]::IndexOf($levels, $cur); $mi = [array]::IndexOf($levels, $min)
        if ($ci -lt 0 -or ($mi -ge 0 -and $ci -lt $mi)) { AddF 'ADSP-DOM-001' 'Fail' $domain.dns_name "Domain functional level '$cur' below policy '$min'." }
        else { AddF 'ADSP-DOM-001' 'Pass' $domain.dns_name 'Domain functional level meets policy.' }
    }

    if ($forest -and $th.min_forest_functional_level) {
        $levels = @('Windows2008Forest','Windows2008R2Forest','Windows2012Forest','Windows2012R2Forest','Windows2016Forest','Windows2019Forest','Windows2022Forest','Windows2025Forest')
        $cur = [string]$forest.functional_level
        $min = [string]$th.min_forest_functional_level
        $ci = [array]::IndexOf($levels, $cur); $mi = [array]::IndexOf($levels, $min)
        if ($ci -lt 0 -or ($mi -ge 0 -and $ci -lt $mi)) { AddF 'ADSP-DOM-002' 'Fail' $forest.name "Forest functional level '$cur' below policy '$min'." }
        else { AddF 'ADSP-DOM-002' 'Pass' $forest.name 'Forest functional level meets policy.' }
    }

    if ($forest) {
        if (-not $forest.recycle_bin_enabled) { AddF 'ADSP-DOM-003' 'Fail' $forest.name 'Recycle Bin not enabled.' }
        else { AddF 'ADSP-DOM-003' 'Pass' $forest.name 'Recycle Bin enabled.' }
    }

    if ($domain -and $null -ne $domain.machine_account_quota) {
        if ([int]$domain.machine_account_quota -gt [int]$th.max_machine_account_quota) {
            AddF 'ADSP-DOM-004' 'Fail' $domain.dns_name "MachineAccountQuota $($domain.machine_account_quota) above policy $($th.max_machine_account_quota)."
        } else { AddF 'ADSP-DOM-004' 'Pass' $domain.dns_name 'MachineAccountQuota within policy.' }
    }

    if ($pp) {
        if ([int]$pp.min_password_length -lt [int]$th.min_password_length) { AddF 'ADSP-DOM-005' 'Fail' 'default-password-policy' "Min length $($pp.min_password_length) below $($th.min_password_length)." }
        else { AddF 'ADSP-DOM-005' 'Pass' 'default-password-policy' 'Min length meets policy.' }
        if ([int]$pp.password_history_count -lt [int]$th.min_password_history) { AddF 'ADSP-DOM-006' 'Fail' 'default-password-policy' 'Password history below policy.' }
        else { AddF 'ADSP-DOM-006' 'Pass' 'default-password-policy' 'Password history meets policy.' }
        if (-not $pp.complexity_enabled) { AddF 'ADSP-DOM-007' 'Fail' 'default-password-policy' 'Complexity not enabled.' }
        else { AddF 'ADSP-DOM-007' 'Pass' 'default-password-policy' 'Complexity enabled.' }
        $lt = [int]$pp.lockout_threshold
        if ($lt -le 0 -or $lt -lt [int]$th.lockout_threshold_min -or $lt -gt [int]$th.lockout_threshold_max) {
            AddF 'ADSP-DOM-008' 'Fail' 'default-password-policy' "Lockout threshold $lt outside policy."
        } else { AddF 'ADSP-DOM-008' 'Pass' 'default-password-policy' 'Lockout threshold within policy.' }
        if ([int]$pp.lockout_duration_minutes -lt [int]$th.lockout_duration_minutes_min) { AddF 'ADSP-DOM-009' 'Fail' 'default-password-policy' 'Lockout duration below policy.' }
        else { AddF 'ADSP-DOM-009' 'Pass' 'default-password-policy' 'Lockout duration meets policy.' }
    }

    $km = $Snapshot.kerberos_metadata
    if ($km -and $null -ne $km.max_ticket_age_hours) {
        if ([int]$km.max_ticket_age_hours -gt 10 -or [int]$km.max_ticket_age_hours -lt 1) {
            AddF 'ADSP-DOM-010' 'Fail' 'kerberos-policy' "Ticket lifetime $($km.max_ticket_age_hours)h outside configured expectation."
        } else { AddF 'ADSP-DOM-010' 'Pass' 'kerberos-policy' 'Ticket lifetime within expectation.' }
    } else {
        AddF 'ADSP-DOM-010' 'Unavailable' 'kerberos-policy' 'Kerberos ticket policy unavailable from snapshot.'
    }

    foreach ($u in @($Snapshot.users)) {
        if ($u.sam_account_name -eq 'Guest' -and $u.enabled) { AddF 'ADSP-DOM-011' 'Fail' $u.object_guid 'Built-in Guest account enabled.' }
        if ($u.sam_account_name -eq 'Administrator' -and $u.password_age_days -gt [int]$th.max_privileged_password_age_days) {
            AddF 'ADSP-DOM-012' 'Fail' $u.object_guid "Administrator password age $($u.password_age_days)d exceeds threshold."
        }
        if ($u.sam_account_name -eq 'krbtgt' -and $u.password_age_days -gt [int]$th.max_krbtgt_password_age_days) {
            AddF 'ADSP-DOM-013' 'Fail' $u.object_guid "krbtgt password age $($u.password_age_days)d exceeds threshold. Plan reset carefully with replication validation."
        }
    }
    if (-not (@($Snapshot.users) | Where-Object { $_.sam_account_name -eq 'Guest' -and $_.enabled })) {
        if ($ruleMap.ContainsKey('ADSP-DOM-011')) { AddF 'ADSP-DOM-011' 'Pass' 'Guest' 'Guest not enabled (or not present as enabled).' }
    }

    $dcCount = @($Snapshot.domain_controllers).Count
    if ($dcCount -lt 1) { AddF 'ADSP-DOM-014' 'Unavailable' 'domain-controllers' 'DC inventory missing; site coverage cannot be verified.' }
    else { AddF 'ADSP-DOM-014' 'Pass' 'domain-controllers' "Collected $dcCount domain controller object(s). Site coverage still requires operational review." }

    return @($out.ToArray())
}

