function Invoke-ADSPEvalAcl {
    param($Snapshot, $Policy, $Rules)
    if ($null -eq $Policy) { throw 'Policy is required.' }
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'acl' -Message $msg)) | Out-Null
    }
    $acls = @($Snapshot.critical_object_acls)
    if ($acls.Count -eq 0) {
        AddF 'ADSP-ACL-019' 'Unavailable' 'acl' 'ACL collection unavailable or incomplete.'
        return @($out.ToArray())
    }
    foreach ($a in $acls) {
        if ($a.object_id -eq 'domain-root' -and $a.right -eq 'GenericAll' -and $a.unexpected) { AddF 'ADSP-ACL-001' 'Fail' $a.principal 'Unexpected GenericAll over domain root.' }
        if ($a.object_id -eq 'domain-root' -and $a.right -eq 'WriteDacl' -and $a.unexpected) { AddF 'ADSP-ACL-002' 'Fail' $a.principal 'Unexpected WriteDacl over domain root.' }
        if ($a.object_id -eq 'domain-root' -and $a.right -eq 'WriteOwner' -and $a.unexpected) { AddF 'ADSP-ACL-003' 'Fail' $a.principal 'Unexpected WriteOwner over domain root.' }
        if ($a.dcsync_like) { AddF 'ADSP-ACL-004' 'Fail' $a.principal 'Principal has replication-change rights consistent with DCSync capability (defensive detection; no exploitation guidance).' }
        if ($a.object_id -eq 'adminsdholder' -and $a.unexpected) { AddF 'ADSP-ACL-005' 'Fail' $a.principal 'Unexpected principal controls AdminSDHolder.' }
        if ($a.modifies_privileged_group) { AddF 'ADSP-ACL-006' 'Fail' $a.principal 'Unexpected principal can modify highest-privilege group membership.' }
        if ($a.reset_privileged_password) { AddF 'ADSP-ACL-007' 'Fail' $a.principal 'Unexpected principal can reset privileged account password.' }
        if ($a.write_spn_privileged) { AddF 'ADSP-ACL-008' 'Fail' $a.principal 'Unexpected principal can write SPNs on privileged/sensitive account.' }
        if ($a.write_delegation_critical) { AddF 'ADSP-ACL-009' 'Fail' $a.principal 'Unexpected principal can write delegation attributes on critical computer.' }
        if ($a.object_id -eq 'domain-controllers-ou' -and $a.unexpected) { AddF 'ADSP-ACL-010' 'Fail' $a.principal 'Unexpected principal controls Domain Controllers OU.' }
        if ($a.object_id -eq 'policies-container' -and $a.unexpected) { AddF 'ADSP-ACL-011' 'Fail' $a.principal 'Unexpected principal controls security-relevant GPO container.' }
        if ($a.unexpected_owner) { AddF 'ADSP-ACL-012' 'Fail' $a.object_id 'Critical object owner is unexpected.' }
        if ($a.unresolved_sid) { AddF 'ADSP-ACL-013' 'Fail' $a.principal 'Critical ACL contains unresolved SID.' }
        if ($a.inherited_broad) { AddF 'ADSP-ACL-014' 'Fail' $a.principal 'Inherited ACE creates broad control over critical object.' }
        if ($a.laps_read_broad) { AddF 'ADSP-ACL-015' 'Fail' $a.principal 'Broad principal has LAPS password-read rights.' }
        if ($a.laps_reset_broad) { AddF 'ADSP-ACL-016' 'Fail' $a.principal 'Broad principal has LAPS reset/write rights.' }
        if ($a.create_computer_critical_ou) { AddF 'ADSP-ACL-017' 'Fail' $a.principal 'Broad principal can create computer objects in critical OU.' }
        if ($a.create_user_privileged_ou) { AddF 'ADSP-ACL-018' 'Fail' $a.principal 'Broad principal can create/modify users in privileged OU.' }
        if ($a.unknown_object_guid) { AddF 'ADSP-ACL-020' 'Unavailable' $a.principal 'ACE interpretation ambiguous due to unknown object-specific GUID.' }
    }
    AddF 'ADSP-ACL-019' 'Pass' 'acl' 'ACL collection present.'
    return @($out.ToArray())
}

