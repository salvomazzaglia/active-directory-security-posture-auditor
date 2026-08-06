function Import-ADSPSnapshotInternal {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $full = Assert-ADSPSafePath -Path $Path -AllowAbsolute -MustExist
    $raw = Get-Content -LiteralPath $full -Raw -Encoding UTF8
    if ($raw.Length -gt 80MB) { throw 'Snapshot exceeds size limit (80MB).' }
    $snap = $raw | ConvertFrom-Json
    Assert-ADSPNoBlockedAttributes -Object $snap -PathHint $full
    return $snap
}

function Test-ADSPRuleDefinition {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Rule)
    $required = @('rule_id','title','category','target_type','default_severity','enabled','evaluator','required_snapshot_sections','description','risk','detection_summary','false_positive_considerations','remediation','operational_validation','references','supported_policies','tags','version')
    foreach ($r in $required) {
        if (-not ($Rule.PSObject.Properties.Name -contains $r)) { throw "Rule missing field: $r" }
    }
    $allowed = @('EvalDomainForest','EvalPrivilegedAccess','EvalAccountSecurity','EvalServiceAccounts','EvalKerberos','EvalComputers','EvalLaps','EvalTrusts','EvalGpo','EvalAcl')
    if ($allowed -notcontains $Rule.evaluator) { throw "Unknown evaluator: $($Rule.evaluator)" }
    return $true
}
