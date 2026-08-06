BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Configuration' {
    It 'validates default config' {
        $r = Test-ADSPConfiguration -ConfigPath (Join-Path $RepoRoot 'config/default.config.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json')
        $r.valid | Should -BeTrue
    }
    It 'validates demo config file exists' {
        Test-Path (Join-Path $RepoRoot 'config/demo.config.json') | Should -BeTrue
    }
    It 'validates baseline policy' {
        Test-Path (Join-Path $RepoRoot 'config/baseline.policy.json') | Should -BeTrue
    }
    It 'validates strict policy' {
        Test-Path (Join-Path $RepoRoot 'config/strict.policy.json') | Should -BeTrue
    }
    It 'validates legacy-compatible policy' {
        Test-Path (Join-Path $RepoRoot 'config/legacy-compatible.policy.json') | Should -BeTrue
    }
    It 'rules use allowlisted evaluators only' {
        $allowed = @('EvalDomainForest','EvalPrivilegedAccess','EvalAccountSecurity','EvalServiceAccounts','EvalKerberos','EvalComputers','EvalLaps','EvalTrusts','EvalGpo','EvalAcl')
        foreach ($r in Get-ADSPRule) {
            $allowed | Should -Contain $r.evaluator
        }
    }
    It 'has unique rule IDs' {
        $ids = Get-ADSPRule | ForEach-Object rule_id
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }
    It 'validates suppressions example' {
        $r = Test-ADSPConfiguration -SuppressionsPath (Join-Path $RepoRoot 'config/suppressions.example.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json')
        $r.valid | Should -BeTrue
    }
}
