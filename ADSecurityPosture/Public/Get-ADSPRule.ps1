function Get-ADSPRule {
    [CmdletBinding()]
    param(
        [string]$Category,
        [ValidateSet('Critical','High','Medium','Low','Informational')]$Severity,
        [string]$Target,
        [string]$Policy,
        [Nullable[bool]]$Enabled
    )
    $pack = Get-Content -LiteralPath (Join-Path $script:ADSPRepoRoot 'config/rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $rules = @($pack.rules)
    if ($Category) { $rules = @($rules | Where-Object { $_.category -eq $Category }) }
    if ($Severity) { $rules = @($rules | Where-Object { $_.default_severity -eq $Severity }) }
    if ($Target) { $rules = @($rules | Where-Object { $_.target_type -eq $Target }) }
    if ($Policy) { $rules = @($rules | Where-Object { $_.supported_policies -contains $Policy }) }
    if ($null -ne $Enabled) { $rules = @($rules | Where-Object { [bool]$_.enabled -eq [bool]$Enabled }) }
    return $rules
}
