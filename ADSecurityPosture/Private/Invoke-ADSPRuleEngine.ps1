function Get-ADSPRuleSeverity {
    param($Rule, $Policy)
    $sev = [string]$Rule.default_severity
    $overrideNames = @()
    if ($null -ne $Policy.severity_overrides) {
        $overrideNames = @($Policy.severity_overrides.PSObject.Properties | ForEach-Object { $_.Name })
    }
    if ($overrideNames -contains $Rule.rule_id) {
        $override = [string]($Policy.severity_overrides.($Rule.rule_id))
        $never = @()
        if ($Policy.never_downgrade_rules) { $never = @($Policy.never_downgrade_rules) }
        if ($never -contains $Rule.rule_id) {
            $order = @{ Informational = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
            if ($order[$override] -ge $order[$sev]) { $sev = $override }
        } else {
            $sev = $override
        }
    }
    return $sev
}

function Invoke-ADSPRuleEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)]$Policy,
        [object[]]$Suppressions
    )
    $rulesPath = Join-Path $script:ADSPRepoRoot 'config/rules.json'
    $pack = Get-Content -LiteralPath $rulesPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $findings = New-Object System.Collections.Generic.List[object]
    $evaluators = @{
        'EvalDomainForest' = ${function:Invoke-ADSPEvalDomainForest}
        'EvalPrivilegedAccess' = ${function:Invoke-ADSPEvalPrivilegedAccess}
        'EvalAccountSecurity' = ${function:Invoke-ADSPEvalAccountSecurity}
        'EvalServiceAccounts' = ${function:Invoke-ADSPEvalServiceAccounts}
        'EvalKerberos' = ${function:Invoke-ADSPEvalKerberos}
        'EvalComputers' = ${function:Invoke-ADSPEvalComputers}
        'EvalLaps' = ${function:Invoke-ADSPEvalLaps}
        'EvalTrusts' = ${function:Invoke-ADSPEvalTrusts}
        'EvalGpo' = ${function:Invoke-ADSPEvalGpo}
        'EvalAcl' = ${function:Invoke-ADSPEvalAcl}
    }
    $byEval = $pack.rules | Group-Object evaluator
    foreach ($group in $byEval) {
        $fn = $evaluators[$group.Name]
        if (-not $fn) { throw "Evaluator not registered: $($group.Name)" }
        $partial = & $fn -Snapshot $Snapshot -Policy $Policy -Rules @($group.Group)
        foreach ($f in @($partial)) {
            if ($null -eq $f) { continue }
            $f = Resolve-ADSPSuppression -Finding $f -Suppressions $Suppressions -Policy $Policy
            $findings.Add($f) | Out-Null
        }
    }
    return @($findings.ToArray())
}

function New-ADSPRuleFinding {
    param($Rule, $Policy, $Result, $TargetId = '', $TargetType = '', $Message = '', $Evidence = @{})
    $sev = Get-ADSPRuleSeverity -Rule $Rule -Policy $Policy
    return New-ADSPFinding -RuleId $Rule.rule_id -Title $Rule.title -Category $Rule.category -Severity $sev -Result $Result -TargetId $TargetId -TargetType $TargetType -Message $Message -Evidence $Evidence -Remediation $Rule.remediation
}
