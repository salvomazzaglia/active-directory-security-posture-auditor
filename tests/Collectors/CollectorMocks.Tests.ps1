BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Collector mocks / unavailable modules' {
    It 'marks collector Unavailable when AD module missing' {
        $mod = Get-Module ADSecurityPosture
        $r = & $mod { Invoke-ADSPCollector -CollectorId 'users' -Domain 'corp.example.invalid' -ActiveDirectoryAvailable:$false }
        $r.status | Should -Be 'Unavailable'
    }
}
