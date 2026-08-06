function ConvertTo-ADSPCsvSafe {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $t = [string]$Value
    if ($t.Length -gt 0 -and ($t[0] -in @('=', '+', '-', '@'))) { $t = "'" + $t }
    return $t
}

function New-ADSPCsvReport {
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$OutputDirectory, [string]$PrivacyMode = 'Masked')
    if ($PrivacyMode -notin @('Masked', 'Hashed', 'Full')) {
        throw "Unsupported privacy mode: $PrivacyMode"
    }
    $alias = @{}
    function Mask($v, $k) { ConvertTo-ADSPPrivacyValue -Value $v -PrivacyMode $PrivacyMode -Kind $k -AliasMap $alias }

    $findingsPath = Join-Path $OutputDirectory 'findings.csv'
    $rows = foreach ($f in @($Report.findings)) {
        if ($null -eq $f) { continue }
        [pscustomobject]@{
            rule_id = ConvertTo-ADSPCsvSafe (Get-ADSPProp $f 'rule_id' '')
            severity = ConvertTo-ADSPCsvSafe (Get-ADSPProp $f 'severity' '')
            result = ConvertTo-ADSPCsvSafe (Get-ADSPProp $f 'result' '')
            category = ConvertTo-ADSPCsvSafe (Get-ADSPProp $f 'category' '')
            title = ConvertTo-ADSPCsvSafe (Get-ADSPProp $f 'title' '')
            target_id = ConvertTo-ADSPCsvSafe (Mask (Get-ADSPProp $f 'target_id' '') 'generic')
            message = ConvertTo-ADSPCsvSafe (Get-ADSPProp $f 'message' '')
            suppressed = [bool](Get-ADSPProp $f 'suppressed' $false)
        }
    }
    @($rows) | Export-Csv -LiteralPath $findingsPath -NoTypeInformation -Encoding UTF8

    $privPath = Join-Path $OutputDirectory 'privileged-membership.csv'
    $memberships = @()
    $pas = Get-ADSPProp $Report 'privileged_access_summary' $null
    if ($null -ne $pas) { $memberships = @(Get-ADSPProp $pas 'memberships' @()) }
    $privRows = foreach ($m in $memberships) {
        if ($null -eq $m) { continue }
        [pscustomobject]@{
            group = ConvertTo-ADSPCsvSafe (Mask (Get-ADSPProp $m 'group_sam' '') 'group')
            member = ConvertTo-ADSPCsvSafe (Mask (Get-ADSPProp $m 'member_sam' '') 'user')
            membership_type = ConvertTo-ADSPCsvSafe (Get-ADSPProp $m 'membership_type' '')
            path_depth = Get-ADSPProp $m 'path_depth' 0
        }
    }
    if (@($privRows).Count -eq 0) {
        [pscustomobject]@{ group=''; member=''; membership_type=''; path_depth=0 } | Export-Csv -LiteralPath $privPath -NoTypeInformation -Encoding UTF8
    } else {
        @($privRows) | Export-Csv -LiteralPath $privPath -NoTypeInformation -Encoding UTF8
    }

    $filters = @{
        'accounts-requiring-review.csv' = { param($f) (Get-ADSPProp $f 'category' '') -match 'Account|Privileged' }
        'service-accounts.csv' = { param($f) (Get-ADSPProp $f 'category' '') -match 'Service' }
        'delegation-findings.csv' = { param($f) (Get-ADSPProp $f 'category' '') -match 'Kerberos|delegation' }
        'laps-coverage.csv' = { param($f) (Get-ADSPProp $f 'category' '') -match 'LAPS' }
        'critical-acl-findings.csv' = { param($f) (Get-ADSPProp $f 'category' '') -match 'ACL' }
    }
    foreach ($name in $filters.Keys) {
        $predicate = $filters[$name]
        $subset = foreach ($f in @($Report.findings)) {
            if ($null -eq $f) { continue }
            if (-not (& $predicate $f)) { continue }
            [pscustomobject]@{
                rule_id = Get-ADSPProp $f 'rule_id' ''
                severity = Get-ADSPProp $f 'severity' ''
                target_id = ConvertTo-ADSPCsvSafe (Mask (Get-ADSPProp $f 'target_id' '') 'generic')
                result = Get-ADSPProp $f 'result' ''
                message = ConvertTo-ADSPCsvSafe (Get-ADSPProp $f 'message' '')
            }
        }
        $path = Join-Path $OutputDirectory $name
        if (@($subset).Count -eq 0) {
            [pscustomobject]@{ rule_id=''; severity=''; target_id=''; result=''; message='none' } | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        } else {
            @($subset) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        }
    }
}
