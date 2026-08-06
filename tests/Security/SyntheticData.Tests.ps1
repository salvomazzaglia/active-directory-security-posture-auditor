BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Synthetic data' {
    It 'New-ADSPSyntheticSnapshot never requires ActiveDirectory module' {
        Get-Module ActiveDirectory | Should -BeNullOrEmpty
        $s = New-ADSPSyntheticSnapshot
        $s.source_mode | Should -Be 'Synthetic'
    }
    It 'uses synthetic identity names' {
        $s = New-ADSPSyntheticSnapshot
        ($s.users | ForEach-Object sam_account_name) | Should -Contain 'synthetic-admin'
    }
}
