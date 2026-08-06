BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Kerberos and delegation rules' {
    It 'has at least 11 rules' { @(Get-ADSPRule -Category 'Kerberos and delegation').Count | Should -BeGreaterOrEqual 22 }
    It 'includes ADSP-KRB-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-001').Count | Should -Be 1 }
    It 'includes ADSP-KRB-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-002').Count | Should -Be 1 }
    It 'includes ADSP-KRB-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-003').Count | Should -Be 1 }
    It 'includes ADSP-KRB-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-004').Count | Should -Be 1 }
    It 'includes ADSP-KRB-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-005').Count | Should -Be 1 }
    It 'includes ADSP-KRB-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-006').Count | Should -Be 1 }
    It 'includes ADSP-KRB-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-007').Count | Should -Be 1 }
    It 'includes ADSP-KRB-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-KRB-008').Count | Should -Be 1 }
}
