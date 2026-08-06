function Get-ADSPRuleHelp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RuleId)
    $rule = Get-ADSPRule | Where-Object { $_.rule_id -eq $RuleId } | Select-Object -First 1
    if (-not $rule) { throw "Unknown rule: $RuleId" }
    return $rule
}
