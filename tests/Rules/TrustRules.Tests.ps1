BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Trusts rules' {
    It 'has at least 5 rules' { @(Get-ADSPRule -Category 'Trusts').Count | Should -BeGreaterOrEqual 10 }
    It 'includes ADSP-TRU-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-TRU-001').Count | Should -Be 1 }
    It 'includes ADSP-TRU-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-TRU-002').Count | Should -Be 1 }
    It 'includes ADSP-TRU-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-TRU-003').Count | Should -Be 1 }
    It 'includes ADSP-TRU-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-TRU-004').Count | Should -Be 1 }
    It 'includes ADSP-TRU-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-TRU-005').Count | Should -Be 1 }
    It 'includes ADSP-TRU-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-TRU-006').Count | Should -Be 1 }
    It 'includes ADSP-TRU-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-TRU-007').Count | Should -Be 1 }
    It 'includes ADSP-TRU-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-TRU-008').Count | Should -Be 1 }
}
