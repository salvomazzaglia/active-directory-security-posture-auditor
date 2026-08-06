BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Comparison' {
    It 'compares before/after synthetic snapshots' {
        $out = Join-Path $RepoRoot ("temp/cmp-test-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        $c = Compare-ADSPSnapshot -Before (Join-Path $RepoRoot 'examples/comparison/before.json') -After (Join-Path $RepoRoot 'examples/comparison/after.json') -PolicyPath (Join-Path $RepoRoot 'config/baseline.policy.json') -OutputDirectory $out -PrivacyMode Masked
        $c.synthetic | Should -BeTrue
        Test-Path (Join-Path $out 'comparison.json') | Should -BeTrue
    }
}
