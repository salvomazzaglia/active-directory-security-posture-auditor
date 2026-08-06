BeforeAll {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepoRoot 'ADSecurityPosture/ADSecurityPosture.psd1') -Force
}
Describe 'Live collection guards' {
    It 'refuses without AcknowledgeLiveDirectoryQuery' {
        { Export-ADSPLiveSnapshot -AuthorizedUse -Domain 'corp.example.invalid' -CollectionProfile Minimal -OutputDirectory (Join-Path $RepoRoot 'temp/live-should-fail') } | Should -Throw
    }
    It 'refuses without AuthorizedUse' {
        { Export-ADSPLiveSnapshot -AcknowledgeLiveDirectoryQuery -Domain 'corp.example.invalid' -CollectionProfile Minimal -OutputDirectory (Join-Path $RepoRoot 'temp/live-should-fail2') } | Should -Throw
    }
}
