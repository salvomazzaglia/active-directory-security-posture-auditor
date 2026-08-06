BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Critical-object ACLs rules' {
    It 'has at least 10 rules' { @(Get-ADSPRule -Category 'Critical-object ACLs').Count | Should -BeGreaterOrEqual 20 }
    It 'includes ADSP-ACL-001' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACL-001').Count | Should -Be 1 }
    It 'includes ADSP-ACL-002' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACL-002').Count | Should -Be 1 }
    It 'includes ADSP-ACL-003' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACL-003').Count | Should -Be 1 }
    It 'includes ADSP-ACL-004' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACL-004').Count | Should -Be 1 }
    It 'includes ADSP-ACL-005' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACL-005').Count | Should -Be 1 }
    It 'includes ADSP-ACL-006' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACL-006').Count | Should -Be 1 }
    It 'includes ADSP-ACL-007' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACL-007').Count | Should -Be 1 }
    It 'includes ADSP-ACL-008' { @(Get-ADSPRule | Where-Object rule_id -eq 'ADSP-ACL-008').Count | Should -Be 1 }
}
