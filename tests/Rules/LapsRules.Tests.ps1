BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Windows LAPS rules' {
    It 'has at least 6 rules' { @(Get-ADSPRule -Category 'Windows LAPS').Count | Should -BeGreaterOrEqual 12 }
    It 'includes ADSP-LAPS-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-LAPS-001').Count | Should -Be 1 }
    It 'includes ADSP-LAPS-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-LAPS-002').Count | Should -Be 1 }
    It 'includes ADSP-LAPS-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-LAPS-003').Count | Should -Be 1 }
    It 'includes ADSP-LAPS-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-LAPS-004').Count | Should -Be 1 }
    It 'includes ADSP-LAPS-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-LAPS-005').Count | Should -Be 1 }
    It 'includes ADSP-LAPS-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-LAPS-006').Count | Should -Be 1 }
    It 'includes ADSP-LAPS-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-LAPS-007').Count | Should -Be 1 }
    It 'includes ADSP-LAPS-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-LAPS-008').Count | Should -Be 1 }
}
