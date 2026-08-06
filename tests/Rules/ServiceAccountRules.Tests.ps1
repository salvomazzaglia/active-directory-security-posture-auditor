BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Service accounts and gMSA rules' {
    It 'has at least 7 rules' { @(Get-ADSPRule -Category 'Service accounts and gMSA').Count | Should -BeGreaterOrEqual 15 }
    It 'includes ADSP-SVC-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-SVC-001').Count | Should -Be 1 }
    It 'includes ADSP-SVC-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-SVC-002').Count | Should -Be 1 }
    It 'includes ADSP-SVC-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-SVC-003').Count | Should -Be 1 }
    It 'includes ADSP-SVC-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-SVC-004').Count | Should -Be 1 }
    It 'includes ADSP-SVC-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-SVC-005').Count | Should -Be 1 }
    It 'includes ADSP-SVC-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-SVC-006').Count | Should -Be 1 }
    It 'includes ADSP-SVC-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-SVC-007').Count | Should -Be 1 }
    It 'includes ADSP-SVC-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-SVC-008').Count | Should -Be 1 }
}
