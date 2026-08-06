BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
    $script:AllRules = @(Get-ADSPRule)
    $script:Report = Invoke-ADSPSecurityAudit -SnapshotPath (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -PrivacyMode Masked -FailOn Critical
}
Describe 'Rule registry Critical/High coverage' {
    It 'defines Critical rule ADSP-PRV-003' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-003').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-PRV-018' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-018').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACC-001' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACC-001').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACC-003' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACC-003').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-SVC-005' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-005').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-KRB-008' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-008').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-KRB-009' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-009').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-KRB-022' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-022').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-CMP-005' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-CMP-005').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-LAPS-006' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-LAPS-006').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-LAPS-012' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-LAPS-012').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACL-001' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-001').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACL-002' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-002').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACL-003' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-003').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACL-004' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-004').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACL-005' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-005').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACL-006' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-006').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACL-010' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-010').default_severity | Should -Be 'Critical' }
    It 'defines Critical rule ADSP-ACL-015' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-015').default_severity | Should -Be 'Critical' }
    It 'defines High rule ADSP-DOM-001' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-DOM-001').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-DOM-002' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-DOM-002').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-DOM-005' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-DOM-005').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-DOM-007' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-DOM-007').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-DOM-011' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-DOM-011').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-DOM-013' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-DOM-013').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-001' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-001').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-002' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-002').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-004' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-004').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-005' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-005').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-006' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-006').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-007' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-007').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-008' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-008').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-012' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-012').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-013' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-013').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-PRV-017' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-PRV-017').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACC-004' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACC-004').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACC-005' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACC-005').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACC-016' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACC-016').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-SVC-001' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-001').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-SVC-003' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-003').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-SVC-006' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-006').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-SVC-008' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-008').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-SVC-009' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-009').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-SVC-010' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-010').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-SVC-012' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-012').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-SVC-014' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-SVC-014').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-001' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-001').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-004' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-004').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-005' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-005').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-007' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-007').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-010' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-010').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-011' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-011').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-012' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-012').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-013' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-013').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-014' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-014').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-KRB-018' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-KRB-018').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-CMP-004' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-CMP-004').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-CMP-008' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-CMP-008').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-CMP-011' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-CMP-011').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-LAPS-004' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-LAPS-004').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-LAPS-007' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-LAPS-007').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-TRU-002' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-TRU-002').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-TRU-004' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-TRU-004').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-GPO-001' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-GPO-001').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-GPO-003' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-GPO-003').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-GPO-004' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-GPO-004').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-GPO-005' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-GPO-005').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-GPO-013' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-GPO-013').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-GPO-017' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-GPO-017').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACL-007' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-007').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACL-008' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-008').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACL-009' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-009').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACL-011' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-011').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACL-012' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-012').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACL-014' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-014').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACL-016' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-016').default_severity | Should -Be 'High' }
    It 'defines High rule ADSP-ACL-018' { ($script:AllRules | Where-Object rule_id -eq 'ADSP-ACL-018').default_severity | Should -Be 'High' }
}

Describe 'Synthetic audit findings' {
    It 'emits Fail findings for intentional synthetic exposures' {
        @($script:Report.findings | Where-Object result -eq 'Fail').Count | Should -BeGreaterThan 20
    }
    It 'includes privileged disabled membership finding' {
        @($script:Report.findings | Where-Object rule_id -eq 'ADSP-PRV-003').Count | Should -BeGreaterThan 0
    }
    It 'includes PasswordNotRequired finding' {
        @($script:Report.findings | Where-Object rule_id -eq 'ADSP-ACC-001').Count | Should -BeGreaterThan 0
    }
    It 'includes unconstrained delegation finding' {
        @($script:Report.findings | Where-Object rule_id -eq 'ADSP-KRB-008').Count | Should -BeGreaterThan 0
    }
    It 'includes DCSync-like ACL finding' {
        @($script:Report.findings | Where-Object rule_id -eq 'ADSP-ACL-004').Count | Should -BeGreaterThan 0
    }
    It 'includes LAPS broad reader finding' {
        @($script:Report.findings | Where-Object rule_id -eq 'ADSP-LAPS-006').Count | Should -BeGreaterThan 0
    }
    It 'redacts credential clue values' {
        $msgs = @($script:Report.findings | Where-Object rule_id -eq 'ADSP-ACC-016' | ForEach-Object message)
        $msgs.Count | Should -BeGreaterThan 0
        ($msgs -join ' ') | Should -Not -Match 'password\s*=\s*\S+'
        ($msgs -join ' ') | Should -Match 'redacted'
    }
    It 'never contains blocked attribute names as serialized values' {
        $json = $script:Report | ConvertTo-Json -Depth 8 -Compress
        foreach ($a in @('unicodePwd','msLAPS-Password','msDS-ManagedPassword','ms-Mcs-AdmPwd')) {
            $json | Should -Not -Match ('"' + $a + '"\s*:')
        }
    }
}
