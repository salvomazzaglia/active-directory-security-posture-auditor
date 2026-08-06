BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Group Policy and authentication settings rules' {
    It 'has at least 10 rules' { @(Get-ADSPRule -Category 'Group Policy and authentication settings').Count | Should -BeGreaterOrEqual 20 }
    It 'includes ADSP-GPO-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-GPO-001').Count | Should -Be 1 }
    It 'includes ADSP-GPO-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-GPO-002').Count | Should -Be 1 }
    It 'includes ADSP-GPO-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-GPO-003').Count | Should -Be 1 }
    It 'includes ADSP-GPO-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-GPO-004').Count | Should -Be 1 }
    It 'includes ADSP-GPO-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-GPO-005').Count | Should -Be 1 }
    It 'includes ADSP-GPO-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-GPO-006').Count | Should -Be 1 }
    It 'includes ADSP-GPO-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-GPO-007').Count | Should -Be 1 }
    It 'includes ADSP-GPO-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-GPO-008').Count | Should -Be 1 }
}
