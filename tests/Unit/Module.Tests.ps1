BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Module' {
    It 'imports successfully' { Get-Module ADSecurityPosture | Should -Not -BeNullOrEmpty }
    It 'reports version 1.0.0' { Get-ADSPVersion | Should -Be '1.0.0' }
    It 'exports only public functions' {
        $exported = (Get-Module ADSecurityPosture).ExportedFunctions.Keys
        $exported | Should -Contain 'Invoke-ADSPSecurityAudit'
        $exported | Should -Not -Contain 'Invoke-ADSPRuleEngine'
    }
    It 'has approved verbs for exports' {
        $verbs = (Get-Verb).Verb
        foreach ($name in (Get-Module ADSecurityPosture).ExportedFunctions.Keys) {
            $verb = ($name -split '-')[0]
            $verbs | Should -Contain $verb
        }
    }
    It 'lists at least 110 rules' { @(Get-ADSPRule).Count | Should -BeGreaterOrEqual 110 }
}
