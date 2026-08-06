BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'No credential retrieval' {
    It 'blocked attribute list includes LAPS and gMSA secrets' {
        $cfg = Get-Content (Join-Path $RepoRoot 'config/sensitive-attributes.json') -Raw | ConvertFrom-Json
        $cfg.blocked_attributes | Should -Contain 'msLAPS-Password'
        $cfg.blocked_attributes | Should -Contain 'msDS-ManagedPassword'
        $cfg.blocked_attributes | Should -Contain 'unicodePwd'
    }
    It 'case-insensitive blocked attribute detection' {
        $mod = Get-Module ADSecurityPosture
        (& $mod { Test-ADSPBlockedAttribute -Name 'MSLAPS-PASSWORD' }) | Should -BeTrue
    }
    It 'sample reports omit blocked attributes' {
        $json = Get-Content (Join-Path $RepoRoot 'examples/sample-report.json') -Raw
        $json | Should -Not -Match '"msLAPS-Password"\s*:'
        $json | Should -Not -Match '"msDS-ManagedPassword"\s*:'
    }
}
