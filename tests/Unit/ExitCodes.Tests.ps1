BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
    $script:mod = Get-Module ADSecurityPosture
}
Describe 'Exit codes' {
    It 'returns 2 for synthetic baseline with High findings' {
        $r = Invoke-ADSPSecurityAudit -SnapshotPath (Join-Path $RepoRoot 'examples/synthetic-snapshot/snapshot.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -PrivacyMode Masked -FailOn High
        $r.exit_code | Should -Be 2
    }
    It 'application error maps to 3' {
        $report = [pscustomobject]@{ findings=@(); snapshot_hash_status='Verified'; score=100; snapshot_completeness='Complete'; internal_error=$false }
        $code = & $script:mod { param($r) Get-ADSPExitCode -Report $r -ApplicationError } $report
        $code | Should -Be 3
    }
}
