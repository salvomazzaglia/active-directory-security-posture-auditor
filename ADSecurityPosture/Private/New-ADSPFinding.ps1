function New-ADSPFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Informational')]$Severity,
        [Parameter(Mandatory)][ValidateSet('Fail','Warning','Pass','Unavailable','NotApplicable','Error','Suppressed')]$Result,
        [string]$TargetId = '',
        [string]$TargetType = '',
        [string]$Message = '',
        [hashtable]$Evidence = @{},
        [string]$Remediation = ''
    )
    [pscustomobject]@{
        finding_id = [guid]::NewGuid().ToString()
        rule_id = $RuleId
        title = $Title
        category = $Category
        severity = $Severity
        result = $Result
        target_id = $TargetId
        target_type = $TargetType
        message = $Message
        evidence = $Evidence
        remediation = $Remediation
        suppressed = $false
        suppression_id = $null
    }
}
