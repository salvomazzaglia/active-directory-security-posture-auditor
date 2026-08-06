#Requires -Version 5.1
Set-StrictMode -Version Latest
$script:ADSPModuleRoot = $PSScriptRoot
$script:ADSPRepoRoot = Split-Path -Parent $PSScriptRoot

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue)
foreach ($file in $private) {
    . $file.FullName
}

$public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File -ErrorAction SilentlyContinue)
foreach ($file in $public) {
    . $file.FullName
}

Export-ModuleMember -Function @(
    'Get-ADSPCollectionPlan'
    'New-ADSPSyntheticSnapshot'
    'Export-ADSPLiveSnapshot'
    'Test-ADSPSnapshot'
    'Invoke-ADSPSecurityAudit'
    'Compare-ADSPSnapshot'
    'Export-ADSPReport'
    'Get-ADSPRule'
    'Get-ADSPRuleHelp'
    'Test-ADSPConfiguration'
    'Get-ADSPVersion'
)
