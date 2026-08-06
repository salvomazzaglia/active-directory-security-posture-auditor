BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Domain and forest rules' {
    It 'has at least 7 rules' { @(Get-ADSPRule -Category 'Domain and forest').Count | Should -BeGreaterOrEqual 15 }
    It 'includes ADSP-DOM-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-DOM-001').Count | Should -Be 1 }
    It 'includes ADSP-DOM-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-DOM-002').Count | Should -Be 1 }
    It 'includes ADSP-DOM-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-DOM-003').Count | Should -Be 1 }
    It 'includes ADSP-DOM-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-DOM-004').Count | Should -Be 1 }
    It 'includes ADSP-DOM-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-DOM-005').Count | Should -Be 1 }
    It 'includes ADSP-DOM-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-DOM-006').Count | Should -Be 1 }
    It 'includes ADSP-DOM-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-DOM-007').Count | Should -Be 1 }
    It 'includes ADSP-DOM-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-DOM-008').Count | Should -Be 1 }
}
