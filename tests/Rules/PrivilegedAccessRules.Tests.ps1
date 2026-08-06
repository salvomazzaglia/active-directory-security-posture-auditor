BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Privileged access rules' {
    It 'has at least 11 rules' { @(Get-ADSPRule -Category 'Privileged access').Count | Should -BeGreaterOrEqual 22 }
    It 'includes ADSP-PRV-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-PRV-001').Count | Should -Be 1 }
    It 'includes ADSP-PRV-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-PRV-002').Count | Should -Be 1 }
    It 'includes ADSP-PRV-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-PRV-003').Count | Should -Be 1 }
    It 'includes ADSP-PRV-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-PRV-004').Count | Should -Be 1 }
    It 'includes ADSP-PRV-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-PRV-005').Count | Should -Be 1 }
    It 'includes ADSP-PRV-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-PRV-006').Count | Should -Be 1 }
    It 'includes ADSP-PRV-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-PRV-007').Count | Should -Be 1 }
    It 'includes ADSP-PRV-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-PRV-008').Count | Should -Be 1 }
}
