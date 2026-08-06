BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Account security rules' {
    It 'has at least 10 rules' { @(Get-ADSPRule -Category 'Account security').Count | Should -BeGreaterOrEqual 20 }
    It 'includes ADSP-ACC-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACC-001').Count | Should -Be 1 }
    It 'includes ADSP-ACC-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACC-002').Count | Should -Be 1 }
    It 'includes ADSP-ACC-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACC-003').Count | Should -Be 1 }
    It 'includes ADSP-ACC-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACC-004').Count | Should -Be 1 }
    It 'includes ADSP-ACC-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACC-005').Count | Should -Be 1 }
    It 'includes ADSP-ACC-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACC-006').Count | Should -Be 1 }
    It 'includes ADSP-ACC-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACC-007').Count | Should -Be 1 }
    It 'includes ADSP-ACC-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACC-008').Count | Should -Be 1 }
}
