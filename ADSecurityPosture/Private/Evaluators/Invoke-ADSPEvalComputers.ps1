function Invoke-ADSPEvalComputers {
    param($Snapshot, $Policy, $Rules)
    $out = New-Object System.Collections.Generic.List[object]
    $ruleMap = @{}; foreach ($r in $Rules) { $ruleMap[$r.rule_id] = $r }
    function AddF($id, $result, $target, $msg) {
        if (-not $ruleMap.ContainsKey($id)) { return }
        $out.Add((New-ADSPRuleFinding -Rule $ruleMap[$id] -Policy $Policy -Result $result -TargetId $target -TargetType 'computer' -Message $msg)) | Out-Null
    }
    $osAllow = $null
    $osPath = Join-Path $script:ADSPRepoRoot 'config/supported-os.example.json'
    if (Test-Path -LiteralPath $osPath) { $osAllow = Get-Content $osPath -Raw | ConvertFrom-Json }

    foreach ($c in @($Snapshot.computers)) {
        $sam = Get-ADSPProp $c 'sam_account_name' ''
        $enabled = [bool](Get-ADSPProp $c 'enabled' $false)
        $inactive = [int](Get-ADSPProp $c 'inactive_days' 0)
        $isDc = [bool](Get-ADSPProp $c 'is_domain_controller' $false)
        $os = Get-ADSPProp $c 'operating_system' $null
        if ($enabled -and $inactive -gt [int]$Policy.thresholds.max_inactive_days) { AddF 'ADSP-CMP-001' 'Fail' $sam 'Enabled computer account is stale.' }
        if (-not $enabled -and (Get-ADSPProp $c 'in_sensitive_group' $false)) { AddF 'ADSP-CMP-002' 'Fail' $sam 'Disabled computer retains sensitive group membership.' }
        if ($osAllow -and $os) {
            $ok = $false
            foreach ($pat in @($osAllow.allowed_operating_systems)) {
                if ($os -like $pat) { $ok = $true; break }
            }
            if (-not $ok) { AddF 'ADSP-CMP-003' 'Fail' $sam 'Computer OS outside operator-maintained allowlist.' }
        }
        if ((Get-ADSPProp $c 'unexpected_delegation' $false) -and -not $isDc) { AddF 'ADSP-CMP-008' 'Fail' $sam 'Unexpected delegation on non-DC computer.' }
        if (Get-ADSPProp $c 'unexpected_spn_pattern' $false) { AddF 'ADSP-CMP-009' 'Fail' $sam 'Unexpected SPN pattern (heuristic).' }
        if ((Get-ADSPProp $c 'is_rodc' $false) -and (Get-ADSPProp $c 'prp_unavailable' $false)) { AddF 'ADSP-CMP-010' 'Unavailable' $sam 'RODC PRP metadata unavailable.' }
        if ((Get-ADSPProp $c 'is_rodc' $false) -and (Get-ADSPProp $c 'prp_overly_broad' $false)) { AddF 'ADSP-CMP-011' 'Fail' $sam 'RODC allowed-password-replication metadata appears overly broad.' }
        if ($inactive -gt 90 -and (Get-ADSPProp $c 'rbcd_present' $false)) { AddF 'ADSP-CMP-012' 'Fail' $sam 'Inactive computer retains RBCD metadata.' }
        if ($Policy.thresholds.expect_windows_laps -and -not $isDc -and -not (Get-ADSPProp $c 'laps_expiration_utc' $null)) {
            AddF 'ADSP-CMP-013' 'Fail' $sam 'Computer lacks Windows LAPS expiration metadata where policy expects LAPS.'
        }
        if (Get-ADSPProp $c 'laps_expiration_anomaly' $false) { AddF 'ADSP-CMP-014' 'Fail' $sam 'Computer LAPS expiration appears stale or far in the future.' }
    }
    foreach ($dc in @($Snapshot.domain_controllers)) {
        $sam = Get-ADSPProp $dc 'sam_account_name' ''
        if ([int](Get-ADSPProp $dc 'password_age_days' 0) -gt 60) { AddF 'ADSP-CMP-004' 'Fail' $sam 'Domain controller password age exceeds threshold.' }
        if (-not (Get-ADSPProp $dc 'enabled' $true)) { AddF 'ADSP-CMP-005' 'Fail' $sam 'Domain controller account is disabled.' }
        $dn = Get-ADSPProp $dc 'distinguished_name' ''
        if ($dn -and $dn -notmatch 'OU=Domain Controllers') {
            AddF 'ADSP-CMP-006' 'Fail' $sam 'DC object outside expected Domain Controllers OU.'
        }
        $prot = $dc.PSObject.Properties['protected_from_accidental_deletion']
        if ($null -ne $prot -and -not $prot.Value) {
            AddF 'ADSP-CMP-007' 'Fail' $sam 'DC not protected from accidental deletion.'
        }
    }
    $truncated = @($Snapshot.collectors | Where-Object { $_.collector_id -eq 'domain-controllers' -and (Get-ADSPProp $_ 'truncated' $false) })
    if ($truncated.Count -gt 0 -or @($Snapshot.domain_controllers).Count -eq 0) {
        AddF 'ADSP-CMP-015' 'Fail' 'domain-controllers' 'Domain controller inventory incomplete or truncated.'
    } else { AddF 'ADSP-CMP-015' 'Pass' 'domain-controllers' 'DC inventory present.' }
    return @($out.ToArray())
}
