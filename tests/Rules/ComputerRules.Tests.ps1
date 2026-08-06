BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Computers and domain controllers rules' {
    It 'has at least 7 rules' { @(Get-ADSPRule -Category 'Computers and domain controllers').Count | Should -BeGreaterOrEqual 15 }
    It 'includes ADSP-CMP-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-CMP-001').Count | Should -Be 1 }
    It 'includes ADSP-CMP-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-CMP-002').Count | Should -Be 1 }
    It 'includes ADSP-CMP-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-CMP-003').Count | Should -Be 1 }
    It 'includes ADSP-CMP-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-CMP-004').Count | Should -Be 1 }
    It 'includes ADSP-CMP-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-CMP-005').Count | Should -Be 1 }
    It 'includes ADSP-CMP-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-CMP-006').Count | Should -Be 1 }
    It 'includes ADSP-CMP-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-CMP-007').Count | Should -Be 1 }
    It 'includes ADSP-CMP-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-CMP-008').Count | Should -Be 1 }
}
