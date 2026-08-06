BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Collector allowlist' {
    It 'rejects unknown collector id' {
        $mod = Get-Module ADSecurityPosture
        { & $mod { Invoke-ADSPCollector -CollectorId 'evil-collector' -Domain 'corp.example.invalid' } } | Should -Throw
    }
    It 'collector scripts exist for all profile collectors' {
        $profiles = Get-Content (Join-Path $RepoRoot 'config/collection-profiles.json') -Raw | ConvertFrom-Json
        foreach ($id in $profiles.profiles.Extended.collectors) {
            Test-Path (Join-Path $RepoRoot "collectors/$id.ps1") | Should -BeTrue
        }
    }
}
