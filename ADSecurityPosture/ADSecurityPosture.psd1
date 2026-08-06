@{
    RootModule        = 'ADSecurityPosture.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b8e4f2a1-9c3d-4e7f-a1b2-5d6e7f8a9b0c'
    Author            = 'Salvatore Mazzaglia'
    CompanyName       = 'Independent'
    Copyright         = '(c) 2026 Salvatore Mazzaglia. MIT License.'
    Description       = 'Read-only Active Directory Domain Services security-posture auditor with offline snapshot analysis, policy-driven findings, and privacy-aware reporting.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
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
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('ActiveDirectory', 'Security', 'Identity', 'Posture', 'PowerShell', 'Audit')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/salvomazzaglia/active-directory-security-posture-auditor'
            ReleaseNotes = 'Initial 1.0.0 release.'
        }
    }
}
