BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Delegation-focused rules' {
    It 'includes unconstrained delegation rule' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-008').Count | Should -Be 1 }
    It 'includes protocol transition rule' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-011').Count | Should -Be 1 }
    It 'includes RBCD rule' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-012').Count | Should -Be 1 }
}
